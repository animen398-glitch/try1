"""Overview GUI tab (gui/tab_overview.py, F5) — headless, thread-free.

Like the Timeline/Findings tab tests: the off-GUI queries are plain staticmethods
exercised directly, and the populate/render logic is driven with real data —
never through ``_run_async`` (which spawns a QThread). Projects live under a tmp
base; no Qt threads, no network.
"""

import json

from core.project import ProjectStore
from gui.tab_overview import OverviewTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed_project(base, slug_url='https://x.com', *, scores=(10, 60)):
    """Record N scans (risk per ``scores``) so the portfolio has a row with a
    delta and the series has trend points."""
    project = ProjectStore(base).get_or_create(slug_url)
    for i, score in enumerate(scores):
        sid = f'2026010{i + 1}_000000'
        scan_dir = project.start_scan(sid)
        report = {
            'scan_id': sid, 'finished_at': sid,
            'executive_summary': {
                'risk_level': 'High' if score >= 50 else 'Low',
                'risk_score': score, 'risk_100': score,
                'metrics': {'risk_100': score, 'attack_surface_score': score // 2,
                            'secrets': 1 if score >= 50 else 0,
                            'high': 2 if score >= 50 else 0, 'medium': 1},
            },
            # A little recon data so the attack-surface graph has a category.
            'phases': {'recon': {'status': 'Success',
                                 'data': {'cms': ['WordPress']}}},
        }
        (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        project.record_scan(scan_dir, report)
    return project


def _portfolio(tmp_path):
    _seed_project(tmp_path)
    return OverviewTabMixin._query_overview(str(tmp_path))


# ── build / registration ────────────────────────────────────────────────────────

def test_tab_builds(qapp):
    w = _window(qapp)
    assert hasattr(w, '_overview_widget')
    assert w.overview_table.columnCount() == len(OverviewTabMixin.OVERVIEW_COLUMNS)
    assert set(w.overview_totals) == {k for k, _ in OverviewTabMixin.OVERVIEW_TOTALS}
    assert set(w.overview_sparklines) == {k for k, _ in OverviewTabMixin.OVERVIEW_TRENDS}


def test_overview_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Overview' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_overview_reads_portfolio(tmp_path):
    _seed_project(tmp_path)
    out = OverviewTabMixin._query_overview(str(tmp_path))
    assert 'error' not in out
    assert out['totals']['projects'] == 1
    row = out['rows'][0]
    assert row['slug'] == 'x.com'
    assert row['risk_level'] == 'High'
    assert row['risk_delta'] == 50          # 60 − 10


def test_query_overview_series(tmp_path):
    _seed_project(tmp_path, scores=(10, 60))
    out = OverviewTabMixin._query_overview_series(str(tmp_path), 'x.com')
    assert out['slug'] == 'x.com'
    assert [p['risk_score'] for p in out['series']] == [10, 60]


def test_query_overview_series_unknown_project(tmp_path):
    out = OverviewTabMixin._query_overview_series(str(tmp_path), 'nope.com')
    assert 'error' in out and out['slug'] == 'nope.com'


def test_query_overview_empty_base(tmp_path):
    out = OverviewTabMixin._query_overview(str(tmp_path))
    assert out['rows'] == [] and out['totals']['projects'] == 0


# ── populate / render (no async) ──────────────────────────────────────────────────

def test_populate_table_and_totals(qapp, tmp_path):
    w = _window(qapp)
    p = _portfolio(tmp_path)
    w._populate_overview_totals(p['totals'])
    w._populate_overview_table(p['rows'])
    assert w.overview_table.rowCount() == 1
    assert w.overview_table.item(0, 0).text() == 'x.com'
    assert w.overview_table.item(0, 1).text() == 'High'      # risk level cell
    assert w.overview_table.item(0, 3).text() == '+50'       # delta cell
    assert w.overview_totals['projects'].text() == '1'
    assert w.overview_totals['secrets'].text() == '1'
    assert 'High' in w.overview_risk_label.text()


def test_render_heatmap_loads_svg(qapp, tmp_path):
    w = _window(qapp)
    p = _portfolio(tmp_path)
    w._render_overview_heatmap(p['rows'])
    # A loaded, non-empty SVG document → renderer reports a real default size.
    assert w.overview_heatmap.renderer().defaultSize().width() > 0


def test_series_render_sets_sparklines(qapp, tmp_path):
    w = _window(qapp)
    _seed_project(tmp_path)
    # Select the project in the combo WITHOUT firing the async trend reload.
    w.overview_trend_project.blockSignals(True)
    w.overview_trend_project.addItem('x.com (2)', 'x.com')
    w.overview_trend_project.blockSignals(False)

    result = OverviewTabMixin._query_overview_series(str(tmp_path), 'x.com')
    w._on_overview_series_loaded(result)
    for spark in w.overview_sparklines.values():
        assert spark.renderer().defaultSize().width() > 0


def test_on_overview_loaded_error(qapp):
    w = _window(qapp)
    w._on_overview_loaded({'error': 'boom'})
    assert w._overview_loaded is False
    assert 'boom' in w.overview_status.text()


# ── attack-surface graph (T5.4) ───────────────────────────────────────────────────

def test_query_overview_graph_returns_namespaced_svg(tmp_path):
    _seed_project(tmp_path)
    out = OverviewTabMixin._query_overview_graph(str(tmp_path), 'x.com')
    assert out['slug'] == 'x.com'
    assert out['svg'].lstrip().startswith('<svg')
    assert 'xmlns' in out['svg']            # injected for QSvgRenderer
    assert 'WordPress' in out['svg']        # a real category from the report


def test_query_overview_graph_unknown_project(tmp_path):
    out = OverviewTabMixin._query_overview_graph(str(tmp_path), 'nope.com')
    assert 'error' in out and out['slug'] == 'nope.com'


def test_query_overview_graph_no_scans(tmp_path):
    # A project with metadata but no recorded scan → no graph, no crash.
    ProjectStore(str(tmp_path)).get_or_create('https://empty.com')
    out = OverviewTabMixin._query_overview_graph(str(tmp_path), 'empty.com')
    assert out['svg'] is None
