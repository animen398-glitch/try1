"""OSINT Catalog GUI tab (gui/tab_osint_catalog.py, EXT-OSINT F3 tail) — headless.

Report-based (like the Technology Risk / Scan Accuracy tabs): the off-GUI queries
are plain staticmethods exercised directly against a project seeded under a tmp
base, and the populate / selection logic is driven with synthetic workflow rows.
The catalog is per-project, a pure coverage display and read-only.
"""

from core.osint_catalog import WORKFLOWS
from gui.plugin_manager import default_manager
from gui.tab_osint_catalog import OsintCatalogTabMixin
from tests.gui_test_helpers import OsintCatalogHost


def _window(qapp):
    return OsintCatalogHost()


def _seed_project(base):
    """One recorded scan whose report runs the recon + subdomains phases, so the
    infrastructure-recon workflow shows partial/covered coverage."""
    import json

    from core.project import ProjectStore

    project = ProjectStore(base).get_or_create('https://x.com')
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {
        'scan_id': sid, 'finished_at': sid,
        'phases': {
            'recon': {'status': 'Success', 'data': {}},
            'subdomains': {'status': 'Success', 'data': {}},
        },
    }
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)
    return project


# ── build / registration ───────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_osint_catalog_widget')
    assert w.oc_table.columnCount() == len(OsintCatalogTabMixin.OSINT_COLUMNS)


def test_osint_catalog_registered_in_tab_bar(qapp):
    titles = [p.title for p in default_manager()]
    assert 'OSINT Catalog' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_lists_scanned_projects(qapp, tmp_path):
    _seed_project(tmp_path)
    res = OsintCatalogTabMixin._query_oc_projects(str(tmp_path))
    assert any(p.get('slug') == 'x.com' for p in res['projects'])


def test_query_table_assesses_coverage(qapp, tmp_path):
    _seed_project(tmp_path)
    out = OsintCatalogTabMixin._query_oc_table(str(tmp_path), 'x.com')
    assert out['slug'] == 'x.com'
    workflows = out['workflows']
    assert len(workflows) == len(WORKFLOWS)
    # recon + subdomains ran → infrastructure-recon is at least partial.
    infra = next(w for w in workflows if w['id'] == 'infrastructure-recon')
    assert infra['status'] in ('partial', 'covered')
    assert 'recon' in infra['ran']
    summary = out['summary']
    assert summary['total'] == len(WORKFLOWS)


def test_query_table_unknown_project_errors(qapp, tmp_path):
    out = OsintCatalogTabMixin._query_oc_table(str(tmp_path), 'nope.com')
    assert 'error' in out and out['slug'] == 'nope.com'


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo(qapp):
    w = _window(qapp)
    w._apply_osint_catalog = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_oc_loaded({'projects': [
        {'slug': 'x.com', 'scan_count': 1},
        {'slug': 'y.com', 'scan_count': 2},
    ]})
    datas = [w.oc_project.itemData(i) for i in range(w.oc_project.count())]
    assert datas == ['x.com', 'y.com']


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_oc_loaded({'projects': []})
    assert 'Нет проектов' in w.oc_status.text()
    assert w.oc_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w.oc_project.addItem('x.com', 'x.com')   # match the result's slug
    w._on_oc_table_loaded({'slug': 'x.com', 'workflows': [
        {'id': 'infrastructure-recon', 'name': 'Infrastructure Recon',
         'category': 'Digital Infrastructure', 'network': 'active',
         'status': 'partial', 'goal': 'Map the external infrastructure.',
         'engines': ['recon', 'subdomains', 'ct'], 'ran': ['recon', 'subdomains'],
         'missing': ['ct'], 'optional': ['bbot'], 'optional_ran': [],
         'produces': ['assets']},
    ], 'summary': {'total': 1, 'covered': 0, 'partial': 1, 'not_run': 0}})
    assert w.oc_table.rowCount() == 1
    assert w.oc_table.item(0, 0).text() == 'partial'
    assert w.oc_table.item(0, 1).text() == 'Infrastructure Recon'
    assert w.oc_table.item(0, 4).text() == '2/3'   # ran/engines coverage
    assert w.oc_rollup['total'].text() == '1'
    assert w.oc_rollup['partial'].text() == '1'


def test_stale_result_is_discarded(qapp):
    w = _window(qapp)
    w.oc_project.addItem('current.com', 'current.com')
    w._on_oc_table_loaded({'slug': 'other.com', 'workflows': [
        {'id': 'x', 'name': 'X', 'status': 'covered', 'engines': ['recon'],
         'ran': ['recon']}], 'summary': {'total': 1}})
    assert w.oc_table.rowCount() == 0   # result for a non-selected project ignored


# ── selection / detail ──────────────────────────────────────────────────────────

def test_selection_shows_goal_and_engines(qapp):
    w = _window(qapp)
    w._populate_oc_table([{
        'id': 'infrastructure-recon', 'name': 'Infrastructure Recon',
        'category': 'Digital Infrastructure', 'network': 'active',
        'status': 'partial', 'goal': 'Map the external infrastructure.',
        'engines': ['recon', 'subdomains', 'ct'], 'ran': ['recon', 'subdomains'],
        'missing': ['ct'], 'optional': ['bbot'], 'optional_ran': [],
        'produces': ['assets', 'attack_surface'],
    }])
    w.oc_table.selectRow(0)
    text = w.oc_detail.toPlainText()
    assert 'Infrastructure Recon' in text
    assert 'Map the external infrastructure.' in text
    assert '✓ recon' in text
    assert '✗ ct' in text
    assert 'attack_surface' in text
