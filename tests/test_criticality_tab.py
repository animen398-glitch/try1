"""Asset Criticality GUI tab (gui/tab_criticality.py) — headless.

Mirrors test_intelligence_tab / test_assets_tab: off-GUI queries are plain
staticmethods exercised directly, and populate/selection logic is driven with
``_run_async`` stubbed out. The assets DB is the per-test temp file from conftest's
``_isolate_assets_db`` fixture, so ``AssetStore()`` inside the tab and inside the
test share one store. Criticality is per-project, display-only and read-only.
"""

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from gui.tab_criticality import CriticalityTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed():
    s = AssetStore()
    s.sync('p1', 's1', [Asset('domain', 'x.com'), Asset('ip', '1.2.3.4')])
    s.sync('p2', 's1', [Asset('subdomain', 'api.y.com')])
    return s


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_crit_widget')
    assert w.crit_table.columnCount() == len(CriticalityTabMixin.CRIT_COLUMNS)


def test_criticality_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Asset Criticality' in titles


# ── off-GUI queries read the store ─────────────────────────────────────────────

def test_query_projects_lists_asset_projects(qapp):
    _seed()
    res = CriticalityTabMixin._query_crit_projects()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 2
    assert by_name['p2']['total'] == 1


def test_query_table_ranks_by_criticality(qapp):
    _seed()
    out = CriticalityTabMixin._query_crit_table('p1')
    items = out['crit']['items']
    assert items, 'expected at least one asset'
    # ranked criticality-desc: each score >= the next.
    scores = [i['criticality'] for i in items]
    assert scores == sorted(scores, reverse=True)
    # domain (type weight 40) outranks a bare ip (type weight ~25).
    assert items[0]['type'] == 'domain'


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo_without_all_entry(qapp):
    w = _window(qapp)
    w._apply_crit_filter = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_crit_loaded({'projects': [
        {'project': 'p1', 'total': 2, 'active': 2},
        {'project': 'p2', 'total': 1, 'active': 1},
    ]})
    datas = [w.crit_project.itemData(i) for i in range(w.crit_project.count())]
    assert datas == ['p1', 'p2']            # per-project: no "all projects" None


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_crit_loaded({'projects': []})
    assert 'Нет проектов' in w.crit_status.text()
    assert w.crit_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_crit_table_loaded({'project': 'p1', 'crit': {
        'items': [{'id': 'a-1', 'type': 'domain', 'value': 'x.com',
                   'criticality': 65, 'band': 'medium', 'factors': []}],
        'summary': {'assets': 1, 'high_criticality': 0, 'top_criticality': 65},
    }})
    assert w.crit_table.rowCount() == 1
    assert w.crit_table.item(0, 0).text() == '65'
    assert w.crit_table.item(0, 1).text() == 'medium'
    assert w.crit_table.item(0, 3).text() == 'x.com'
    assert w.crit_rollup['assets'].text() == '1'
    assert w.crit_rollup['top_criticality'].text() == '65'


# ── selection / detail ──────────────────────────────────────────────────────────

def test_selection_shows_factors(qapp):
    w = _window(qapp)
    w._populate_crit_table([{
        'id': 'a-1', 'type': 'domain', 'value': 'x.com',
        'criticality': 60, 'band': 'medium',
        'factors': [{'factor': 'Тип актива: domain', 'points': 40},
                    {'factor': 'Публично доступен (2xx)', 'points': 5}],
    }])
    w.crit_table.selectRow(0)
    text = w.crit_detail.toPlainText()
    assert 'x.com' in text
    assert '+40' in text and 'Тип актива: domain' in text
