"""Attack Paths GUI tab (gui/tab_attack_paths.py) — headless.

Mirrors test_intelligence_tab / test_criticality_tab: off-GUI queries are plain
staticmethods exercised directly, and populate/selection logic is driven with
``_run_async`` stubbed out. The assets DB is the per-test temp file from conftest's
``_isolate_assets_db`` fixture. Attack paths are per-project, display-only and
read-only — populate/selection are tested with synthetic path rows (the path
derivation itself is covered in test_intelligence).
"""

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from gui.tab_attack_paths import AttackPathsTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed():
    s = AssetStore()
    s.sync('p1', 's1', [Asset('subdomain', 'api.x.com'), Asset('ip', '1.2.3.4')])
    return s


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_attack_paths_widget')
    assert w.path_table.columnCount() == len(AttackPathsTabMixin.PATH_COLUMNS)


def test_attack_paths_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Attack Paths' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_lists_asset_projects(qapp):
    _seed()
    res = AttackPathsTabMixin._query_path_projects()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2

def test_query_table_returns_paths_shape(qapp):
    _seed()
    out = AttackPathsTabMixin._query_path_table('p1')
    # a project with no shared-infra clusters yields an empty (but well-formed) view.
    assert 'paths' in out['paths'] and 'summary' in out['paths']


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo_without_all_entry(qapp):
    w = _window(qapp)
    w._apply_path_filter = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_path_loaded({'projects': [
        {'project': 'p1', 'total': 2, 'active': 2},
        {'project': 'p2', 'total': 1, 'active': 1},
    ]})
    datas = [w.path_project.itemData(i) for i in range(w.path_project.count())]
    assert datas == ['p1', 'p2']            # per-project: no "all projects" None


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_path_loaded({'projects': []})
    assert 'Нет проектов' in w.path_status.text()
    assert w.path_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_path_table_loaded({'project': 'p1', 'paths': {
        'paths': [{'score': 55, 'band': 'medium', 'entry': 'api.x.com',
                   'entry_severity': 'high', 'pivot_type': 'ip',
                   'pivot_node': '1.2.3.4', 'size': 3,
                   'targets': ['a.x.com', 'b.x.com'], 'critical_targets': 1}],
        'summary': {'paths': 1, 'critical_paths': 0, 'top_score': 55},
    }})
    assert w.path_table.rowCount() == 1
    assert w.path_table.item(0, 0).text() == '55'
    assert w.path_table.item(0, 1).text() == 'medium'
    assert w.path_table.item(0, 2).text() == 'api.x.com'
    assert w.path_table.item(0, 3).text() == 'ip 1.2.3.4'
    assert w.path_table.item(0, 4).text() == '2'        # target count
    assert w.path_table.item(0, 5).text() == '1'        # critical targets
    assert w.path_rollup['paths'].text() == '1'
    assert w.path_rollup['top_score'].text() == '55'


# ── selection / detail ──────────────────────────────────────────────────────────

def test_table_load_error_clears_stale_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_path_table_loaded({'project': 'p1', 'paths': {
        'paths': [{'score': 55, 'band': 'medium', 'entry': 'api.x.com',
                   'entry_severity': 'high', 'pivot_type': 'ip',
                   'pivot_node': '1.2.3.4', 'size': 3,
                   'targets': ['a.x.com'], 'critical_targets': 1}],
        'summary': {'paths': 1, 'critical_paths': 0, 'top_score': 55},
    }})
    w.path_table.selectRow(0)
    assert w.path_table.rowCount() == 1

    w._on_path_table_loaded({'project': 'p1', 'error': 'boom'})

    assert w.path_table.rowCount() == 0
    assert w.path_detail.toPlainText() == ''
    assert w.path_rollup['paths'].text() == '0'
    assert w._path_records == []
    assert 'boom' in w.path_status.text()


def test_selection_shows_chain(qapp):
    w = _window(qapp)
    w._populate_path_table([{
        'score': 55, 'band': 'medium', 'entry': 'api.x.com',
        'entry_severity': 'high', 'pivot_type': 'ip', 'pivot_node': '1.2.3.4',
        'size': 3, 'targets': ['a.x.com', 'b.x.com'], 'critical_targets': 1,
    }])
    w.path_table.selectRow(0)
    text = w.path_detail.toPlainText()
    assert 'api.x.com' in text
    assert 'ip 1.2.3.4' in text
    assert 'a.x.com' in text and 'b.x.com' in text
