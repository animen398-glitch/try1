"""Overview GUI tab (gui/tab_overview.py, F5) — headless, thread-free.

Like the Timeline/Findings tab tests: the off-GUI queries are plain staticmethods
exercised directly, and the populate/render logic is driven with real data —
never through ``_run_async`` (which spawns a QThread). Projects live under a tmp
base; no Qt threads, no network.
"""

import json

from core.project import ProjectStore
from gui.plugin_manager import default_manager
from gui.tab_overview import OverviewTabMixin
from tests.gui_test_helpers import OverviewHost


def _window(qapp):
    return OverviewHost()


def _seed_project(base, slug_url='https://x.com', *, scores=(10, 60)):
    """Record N scans (risk per ``scores``) so the portfolio has a row with a
    delta and the series has trend points."""
    project = ProjectStore(base).get_or_create(slug_url)
    for i, score in enumerate(scores):
        sid = f'2026010{i + 1}_000000'
        scan_dir = project.start_scan(sid)
        report = {
            'scan_id': sid, 'finished_at': sid,
            'warnings': ([{'stage': 'evidence', 'message': 'manifest failed'}]
                         if score >= 50 else []),
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
    titles = [p.title for p in default_manager()]
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
    assert row['warning_count'] == 1


def test_query_overview_attaches_missions_overview(tmp_path):
    from core import pentest_mission as pm
    from core.mission_store import MissionStore
    _seed_project(tmp_path)
    MissionStore().save_mission(
        pm.advance_mission_status(
            pm.create_mission('x.com', 'review', allowed_actions=['headers_check']),
            'ready'))

    out = OverviewTabMixin._query_overview(str(tmp_path))
    assert out['missions_overview']['total'] == 1
    assert out['missions_overview']['counts']['ready'] == 1


def test_populate_overview_missions_cards(qapp):
    w = OverviewHost()
    w._populate_overview_missions({
        'total': 3, 'client_facing': 5,
        'counts': {'ready': 1, 'running': 0, 'completed': 2, 'failed': 0},
        'missions': [{'mission_id': 'm1', 'objective': 'Review',
                      'status': 'completed', 'last_run_id': 'mrun-1',
                      'last_run_status': 'completed', 'client_facing': 5}],
    })
    assert w.overview_mission_cards['total'].text() == '3'
    assert w.overview_mission_cards['completed'].text() == '2'
    assert w.overview_mission_cards['client_facing'].text() == '5'
    assert 'Review' in w.overview_mission_recent.text()


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
    assert w.overview_table.item(0, 8).text() == '1'         # warnings cell
    assert 'evidence: manifest failed' in w.overview_table.item(0, 8).toolTip()
    assert w.overview_totals['projects'].text() == '1'
    assert w.overview_totals['secrets'].text() == '1'
    assert w.overview_totals['warning_count'].text() == '1'
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


def test_overview_load_error_clears_stale_portfolio_state(qapp, tmp_path):
    w = _window(qapp)
    p = _portfolio(tmp_path)
    companies = [{'slug': 'acme', 'name': 'Acme', 'project_count': 1,
                  'risk_level': 'High', 'risk_score': 60, 'secrets': 1,
                  'high': 2, 'medium': 1, 'warning_count': 1,
                  'active_findings': 3, 'asset_total': 4,
                  'project_slugs': ['x.com']}]
    w._overview_companies = companies
    w._populate_overview_companies(companies)
    w._populate_assign_combo(companies)
    w._on_overview_loaded(p)
    assert w.overview_table.rowCount() == 1
    assert w.overview_trend_project.count() == 1
    assert w.overview_totals['projects'].text() == '1'

    w._on_overview_loaded({'error': 'boom'})

    assert w._overview_loaded is False
    assert w._overview_rows == []
    assert w._overview_companies == []
    assert w._overview_company_filter is None
    assert w.overview_table.rowCount() == 0
    assert w.overview_companies_table.rowCount() == 0
    assert w.overview_trend_project.count() == 0
    assert w.overview_totals['projects'].text() == '0'
    assert w.overview_assign_company.count() == 1
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


# ── scan retention (Prune old scans) ──────────────────────────────────────────

def test_do_prune_scans_deletes_artifacts_keeps_index(tmp_path):
    from core.retention import plan_retention
    project = ProjectStore(str(tmp_path)).get_or_create('https://x.com')
    for i in range(1, 4):
        sid = f'2026010{i}_000000'
        d = project.start_scan(sid)
        (d / 'report.json').write_text('{}', encoding='utf-8')
        project.record_scan(d, {'scan_id': sid, 'finished_at': f'2026-01-0{i}T00:00:00',
                                'executive_summary': {'risk_score': i, 'metrics': {}}})

    plan = plan_retention(project, keep_last=1)
    out = OverviewTabMixin._do_prune_scans(str(tmp_path), 'x.com', plan)
    assert 'error' not in out
    assert set(out['pruned']) == {'20260101_000000', '20260102_000000'}
    assert not (project.root / 'scans' / '20260101_000000').exists()
    assert (project.root / 'scans' / '20260103_000000').exists()   # newest kept
    assert len(project.scans()) == 3                                # index intact


def test_do_prune_scans_unknown_project(tmp_path):
    out = OverviewTabMixin._do_prune_scans(str(tmp_path), 'nope.com', {'prune': ['x']})
    assert 'error' in out


def test_do_restore_all_rejects_non_backup(tmp_path):
    # the restore worker surfaces a bad archive as an error dict (never crashes
    # the UI); core.backup itself is covered in test_backup.py
    import zipfile
    junk = tmp_path / 'junk.zip'
    with zipfile.ZipFile(junk, 'w') as zf:
        zf.writestr('x.txt', 'nope')
    out = OverviewTabMixin._do_restore_all(str(junk), False)
    assert 'error' in out


# ── F-C3: company roll-up, filter, assignment ─────────────────────────────────

def test_company_table_built(qapp):
    w = _window(qapp)
    assert (w.overview_companies_table.columnCount()
            == len(OverviewTabMixin.OVERVIEW_COMPANY_COLUMNS))


def test_query_companies_reads_view(tmp_path):
    _seed_project(tmp_path, 'https://x.com')
    ProjectStore(str(tmp_path)).assign('x.com', 'acme_corp')
    out = OverviewTabMixin._query_companies(str(tmp_path))
    assert 'error' not in out
    by_slug = {r['slug']: r for r in out['rows']}
    assert by_slug['acme_corp']['project_count'] == 1
    assert by_slug['acme_corp']['risk_level'] == 'High'


def test_populate_companies_and_assign_combo(qapp, tmp_path):
    from core.company import CompanyRegistry
    w = _window(qapp)
    CompanyRegistry().create('Acme Corp')
    rows = [{'slug': 'acme_corp', 'name': 'Acme Corp', 'project_count': 2,
             'risk_level': 'High', 'risk_score': 70, 'secrets': 3, 'high': 1,
             'medium': 0, 'warning_count': 4, 'active_findings': 5, 'asset_total': 12,
             'project_slugs': ['a.com', 'b.com']}]
    w._populate_overview_companies(rows)
    assert w.overview_companies_table.rowCount() == 1
    assert w.overview_companies_table.item(0, 0).text() == 'Acme Corp'
    assert w.overview_companies_table.item(0, 1).text() == '2'
    assert w.overview_companies_table.item(0, 7).text() == '4'
    w._populate_assign_combo(rows)
    items = [w.overview_assign_company.itemText(i)
             for i in range(w.overview_assign_company.count())]
    assert items == ['', 'Acme Corp']            # "" sentinel + company name


def test_company_filter_hides_other_projects(qapp, tmp_path):
    w = _window(qapp)
    w._populate_overview_table([
        {'slug': 'a.com', 'risk_level': 'High'},
        {'slug': 'b.com', 'risk_level': 'Low'},
    ])
    rows = [{'slug': 'acme_corp', 'name': 'Acme', 'project_count': 1,
             'risk_level': 'High', 'risk_score': 70, 'secrets': 0, 'high': 0,
             'medium': 0, 'warning_count': 0, 'active_findings': 0, 'asset_total': 0,
             'project_slugs': ['a.com']}]
    w._overview_companies = rows
    w._populate_overview_companies(rows)
    # Select the company row → real signal path filters the projects table.
    w.overview_companies_table.selectRow(0)
    w._on_company_row_selected()                 # deterministic under offscreen Qt
    assert w.overview_table.isRowHidden(0) is False   # a.com kept
    assert w.overview_table.isRowHidden(1) is True    # b.com hidden
    w._clear_company_filter()
    assert w.overview_table.isRowHidden(1) is False   # filter cleared


def test_do_assign_sets_and_clears_company(tmp_path):
    store = ProjectStore(str(tmp_path))
    store.get_or_create('https://x.com')
    out = OverviewTabMixin._do_assign(str(tmp_path), 'x.com', 'Acme Corp')
    assert out['ok'] is True
    assert store.get('x.com').get_company() == 'acme_corp'
    # Empty name unassigns.
    out = OverviewTabMixin._do_assign(str(tmp_path), 'x.com', '')
    assert out['ok'] is True
    assert store.get('x.com').get_company() is None


def test_do_assign_unknown_project(tmp_path):
    out = OverviewTabMixin._do_assign(str(tmp_path), 'ghost.com', 'Acme')
    assert out['ok'] is False


def test_on_assign_done_error(qapp):
    w = _window(qapp)
    w._refresh_overview = lambda: None           # don't spawn the reload worker
    w._on_assign_done({'error': 'boom', 'slug': 'x.com'})
    assert 'boom' in w.overview_status.text()


# ── project bundle export / import (core.project_io wiring) ───────────────────

def test_do_export_bundle_writes_zip(qapp, tmp_path):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    _seed_project(tmp_path)                      # tree under Projects/x.com
    FindingsStore().sync('x.com', 's1', [
        {'category': 'vuln', 'rule_id': 'r0', 'title': 'V', 'severity': 'high',
         'location': 'https://x.com/a'}])
    AssetStore().sync('x.com', 's1', [Asset('domain', 'x.com')])
    bundle = tmp_path / 'x.com.zip'
    res = OverviewTabMixin._do_export_bundle(str(tmp_path), 'x.com', str(bundle))
    assert 'error' not in res
    assert bundle.exists()
    assert res['findings'] == 1 and res['assets'] == 1


def test_do_export_bundle_unknown_project_returns_error(qapp, tmp_path):
    res = OverviewTabMixin._do_export_bundle(str(tmp_path), 'ghost.com',
                                             str(tmp_path / 'g.zip'))
    assert 'error' in res


def test_on_bundle_exported_status_and_error(qapp, monkeypatch):
    import gui.tab_overview as ov
    # The error path shows a modal QMessageBox.critical, which would block under
    # offscreen Qt — stub it so the handler logic is exercised without a dialog.
    monkeypatch.setattr(ov.QMessageBox, 'critical',
                        staticmethod(lambda *a, **k: None))
    w = _window(qapp)
    w._on_bundle_exported({'slug': 'x.com', 'findings': 3, 'assets': 2, 'scans': 1})
    assert 'x.com' in w.overview_status.text()
    w._on_bundle_exported({'error': 'disk full'})    # error path: no crash, no block


def test_on_bundle_imported_variants(qapp):
    w = _window(qapp)
    w._refresh_overview = lambda: None               # don't spawn the reload worker
    w._on_bundle_imported({'slug': 'x.com', 'findings': 2, 'assets': 1, 'files': 5})
    assert 'x.com' in w.overview_status.text() and 'Импортирован' in w.overview_status.text()
    w._on_bundle_imported({'slug': 'y.com', 'skipped': True, 'reason': 'project exists'})
    assert 'Пропущено' in w.overview_status.text()
