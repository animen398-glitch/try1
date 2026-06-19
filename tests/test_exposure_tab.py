"""Asset Exposure GUI tab (gui/tab_exposure.py) — headless.

Mirrors test_criticality_tab: off-GUI queries are plain staticmethods exercised
directly, and populate/selection logic is driven with ``_run_async`` stubbed out.
The assets DB is the per-test temp file from conftest's ``_isolate_assets_db``
fixture, so ``AssetStore()`` inside the tab and inside the test share one store.
Exposure is per-project (likelihood axis), display-only and read-only.
"""

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from gui.tab_exposure import ExposureTabMixin


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
    assert hasattr(w, '_exp_widget')
    assert w.exp_table.columnCount() == len(ExposureTabMixin.EXP_COLUMNS)


def test_exposure_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Asset Exposure' in titles


# ── off-GUI queries read the store ─────────────────────────────────────────────

def test_query_projects_lists_asset_projects(qapp):
    _seed()
    res = ExposureTabMixin._query_exp_projects()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 2
    assert by_name['p2']['total'] == 1


def test_query_table_ranks_by_exposure(qapp):
    _seed()
    out = ExposureTabMixin._query_exp_table('p1')
    items = out['exp']['items']
    assert items, 'expected at least one asset'
    # ranked exposure-desc: each score >= the next.
    scores = [i['exposure'] for i in items]
    assert scores == sorted(scores, reverse=True)


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo_without_all_entry(qapp):
    w = _window(qapp)
    w._apply_exp_filter = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_exp_loaded({'projects': [
        {'project': 'p1', 'total': 2, 'active': 2},
        {'project': 'p2', 'total': 1, 'active': 1},
    ]})
    datas = [w.exp_project.itemData(i) for i in range(w.exp_project.count())]
    assert datas == ['p1', 'p2']            # per-project: no "all projects" None


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_exp_loaded({'projects': []})
    assert 'Нет проектов' in w.exp_status.text()
    assert w.exp_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_exp_table_loaded({'project': 'p1', 'exp': {
        'items': [{'id': 'a-1', 'type': 'subdomain', 'value': 'a.x.com',
                   'exposure': 55, 'band': 'medium', 'factors': []}],
        'summary': {'assets': 1, 'exposed_assets': 0, 'top_exposure': 55},
    }})
    assert w.exp_table.rowCount() == 1
    assert w.exp_table.item(0, 0).text() == '55'
    assert w.exp_table.item(0, 1).text() == 'medium'
    assert w.exp_table.item(0, 3).text() == 'a.x.com'
    assert w.exp_rollup['assets'].text() == '1'
    assert w.exp_rollup['top_exposure'].text() == '55'


# ── selection / detail ──────────────────────────────────────────────────────────

def test_selection_shows_factors(qapp):
    w = _window(qapp)
    w._populate_exp_table([{
        'id': 'a-1', 'type': 'subdomain', 'value': 'a.x.com',
        'exposure': 50, 'band': 'medium',
        'factors': [{'factor': 'Публично доступен (2xx)', 'points': 20},
                    {'factor': 'Открытые находки: 1 (worst high)', 'points': 20}],
    }])
    w.exp_table.selectRow(0)
    text = w.exp_detail.toPlainText()
    assert 'a.x.com' in text
    assert '+20' in text and 'Публично доступен (2xx)' in text
