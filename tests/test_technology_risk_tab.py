"""Technology Risk GUI tab (gui/tab_technology_risk.py, EPIC 15) — headless.

Report-based (like the Scan Accuracy tab): the off-GUI queries are plain
staticmethods exercised directly against a project seeded under a tmp base, and the
populate / selection logic is driven with synthetic rows. Technology risk is
per-project, display-only and read-only.
"""

from gui.plugin_manager import default_manager
from gui.tab_technology_risk import TechnologyRiskTabMixin
from tests.gui_test_helpers import TechnologyRiskHost


def _window(qapp):
    return TechnologyRiskHost()


def _seed_project(base):
    """One recorded scan whose report carries an outdated technology (PHP 5.6) and a
    vulnerable JS dependency (jquery), so build_technology_risk yields items."""
    import json

    from core.project import ProjectStore

    project = ProjectStore(base).get_or_create('https://x.com')
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {
        'scan_id': sid, 'finished_at': sid,
        'phases': {'recon': {'status': 'Success', 'data': {
            'technologies': [{'name': 'PHP', 'version': '5.6', 'category': 'Language'}],
            'dependencies': {'libraries': [
                {'name': 'jquery', 'library': 'jquery', 'version': '1.7.0',
                 'vulnerabilities': [{'cve': 'CVE-2020-11022', 'severity': 'high'}]}]},
        }}},
    }
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)
    return project


# ── build / registration ───────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_technology_risk_widget')
    assert w.tr_table.columnCount() == len(TechnologyRiskTabMixin.TECHRISK_COLUMNS)


def test_technology_risk_registered_in_tab_bar(qapp):
    titles = [p.title for p in default_manager()]
    assert 'Technology Risk' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_lists_scanned_projects(qapp, tmp_path):
    _seed_project(tmp_path)
    res = TechnologyRiskTabMixin._query_tr_projects(str(tmp_path))
    assert any(p.get('slug') == 'x.com' for p in res['projects'])


def test_query_table_scores_items(qapp, tmp_path):
    _seed_project(tmp_path)
    out = TechnologyRiskTabMixin._query_tr_table(str(tmp_path), 'x.com')
    assert out['slug'] == 'x.com'
    items = out['items']
    assert items, 'expected scored items'
    scores = [i['score'] for i in items]
    assert scores == sorted(scores, reverse=True)   # risk-desc
    kinds = {i['kind'] for i in items}
    assert {'technology', 'dependency'} <= kinds
    assert out['summary']['vulnerable_dependencies'] == 1


def test_query_table_unknown_project_errors(qapp, tmp_path):
    out = TechnologyRiskTabMixin._query_tr_table(str(tmp_path), 'nope.com')
    assert 'error' in out and out['slug'] == 'nope.com'


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo(qapp):
    w = _window(qapp)
    w._apply_technology_risk = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_tr_loaded({'projects': [
        {'slug': 'x.com', 'scan_count': 1},
        {'slug': 'y.com', 'scan_count': 2},
    ]})
    datas = [w.tr_project.itemData(i) for i in range(w.tr_project.count())]
    assert datas == ['x.com', 'y.com']


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_tr_loaded({'projects': []})
    assert 'Нет проектов' in w.tr_status.text()
    assert w.tr_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w.tr_project.addItem('x.com', 'x.com')   # match the result's slug
    w._on_tr_table_loaded({'slug': 'x.com', 'items': [
        {'kind': 'dependency', 'name': 'jquery', 'version': '1.7.0', 'score': 40,
         'band': 'medium', 'category': 'JS dependency',
         'reason': '1 known vulnerable advisory/advisories; worst=high',
         'evidence': ['CVE-2020-11022']},
    ], 'summary': {'items': 1, 'high': 0, 'vulnerable_dependencies': 1,
                   'score': 40, 'band': 'medium'}})
    assert w.tr_table.rowCount() == 1
    assert w.tr_table.item(0, 0).text() == '40'
    assert w.tr_table.item(0, 1).text() == 'medium'
    assert w.tr_table.item(0, 3).text() == 'jquery 1.7.0'
    assert w.tr_rollup['items'].text() == '1'
    assert w.tr_rollup['vulnerable_dependencies'].text() == '1'


def test_stale_result_is_discarded(qapp):
    w = _window(qapp)
    w.tr_project.addItem('current.com', 'current.com')
    w._on_tr_table_loaded({'slug': 'other.com', 'items': [
        {'kind': 'technology', 'name': 'PHP', 'version': '5.6', 'score': 35,
         'band': 'medium'}], 'summary': {'items': 1}})
    assert w.tr_table.rowCount() == 0   # result for a non-selected project ignored


# ── selection / detail ──────────────────────────────────────────────────────────

def test_selection_shows_reason_and_evidence(qapp):
    w = _window(qapp)
    w._populate_tr_table([{
        'kind': 'dependency', 'name': 'jquery', 'version': '1.7.0', 'score': 40,
        'band': 'medium', 'category': 'JS dependency',
        'reason': '1 known vulnerable advisory/advisories; worst=high',
        'evidence': ['CVE-2020-11022'],
    }])
    w.tr_table.selectRow(0)
    text = w.tr_detail.toPlainText()
    assert 'jquery 1.7.0' in text
    assert 'worst=high' in text
    assert 'CVE-2020-11022' in text
