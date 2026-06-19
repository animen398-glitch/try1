"""Asset Inventory GUI tab (gui/tab_assets.py) — headless.

Mirrors test_findings_tab: off-GUI queries are plain staticmethods exercised
directly, and populate/selection logic is driven with ``_run_async`` stubbed out.
The assets DB is the per-test temp file from conftest's ``_isolate_assets_db``
fixture, so ``AssetStore()`` inside the tab and inside the test share one store.
Assets are read-only — there is no status-change control to test.
"""

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from gui.plugin_manager import default_manager
from gui.tab_assets import AssetsTabMixin
from tests.gui_test_helpers import AssetsHost


def _window(qapp):
    return AssetsHost()


def _seed():
    s = AssetStore()
    s.sync('p1', 's1', [Asset('subdomain', 'api.x.com'),
                        Asset('ip', '1.2.3.4')])
    s.sync('p2', 's1', [Asset('domain', 'y.com')])
    return s


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_assets_widget')
    assert (w.assets_table.columnCount()
            == len(AssetsTabMixin.ASSETS_COLUMNS))


def test_assets_registered_in_tab_bar(qapp):
    titles = [p.title for p in default_manager()]
    assert 'Assets' in titles


# ── off-GUI queries read the store ─────────────────────────────────────────────

def test_query_assets_lists_projects(qapp):
    _seed()
    res = AssetsTabMixin._query_assets()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 2
    assert by_name['p2']['total'] == 1


def test_query_table_filters_by_project_and_type(qapp):
    _seed()
    all_p1 = AssetsTabMixin._query_assets_table('p1', None, None)
    assert {r['value'] for r in all_p1['rows']} == {'api.x.com', '1.2.3.4'}
    assert all_p1['summary']['total'] == 2
    subs = AssetsTabMixin._query_assets_table('p1', 'subdomain', None)
    assert {r['value'] for r in subs['rows']} == {'api.x.com'}


# ── populate + project selector ────────────────────────────────────────────────

def test_on_assets_loaded_fills_project_combo(qapp):
    w = _window(qapp)
    w._on_assets_loaded({'projects': [
        {'project': 'p1', 'total': 2, 'active': 2},
        {'project': 'p2', 'total': 1, 'active': 1},
    ]})
    datas = [w.assets_project.itemData(i)
             for i in range(w.assets_project.count())]
    assert datas == [None, 'p1', 'p2']


def test_populate_table_rows_and_status_label(qapp):
    w = _window(qapp)
    w._populate_assets_table([
        {'id': 'a-a', 'type': 'subdomain', 'value': 'api.x.com',
         'label': 'api.x.com', 'status': 'ACTIVE',
         'first_seen_at': '2026-01-01T00:00:00',
         'last_seen_at': '2026-01-02T00:00:00'},
    ])
    assert w.assets_table.rowCount() == 1
    assert w.assets_table.item(0, 0).text() == 'subdomain'
    assert w.assets_table.item(0, 1).text() == 'api.x.com'
    assert w.assets_table.item(0, 2).text() == 'Активен'   # STATUS_LABELS
    assert w.assets_table.item(0, 3).text() == '2026-01-01'


def test_rollup_cards_reflect_by_type(qapp):
    w = _window(qapp)
    w._on_assets_table_loaded({
        'rows': [],
        'summary': {'total': 3, 'active': 3,
                    'by_type': {'subdomain': 2, 'ip': 1}},
        'project': 'p1',
    })
    assert w.assets_rollup['subdomain'].text() == '2'
    assert w.assets_rollup['ip'].text() == '1'
    assert w.assets_rollup['domain'].text() == '0'      # absent type → 0


# ── selection wiring (threads stubbed) ─────────────────────────────────────────

def test_selection_shows_detail(qapp):
    w = _window(qapp)
    w._run_async = lambda *a, **k: None     # don't spawn the events worker
    w._populate_assets_table([
        {'id': 'a-a', 'type': 'ip', 'value': '1.2.3.4', 'label': '1.2.3.4',
         'status': 'GONE', 'attrs': {'asn': 'AS13335'},
         'first_seen_at': '2026-01-01', 'last_seen_at': '2026-01-01'},
    ])
    w.assets_table.selectRow(0)
    text = w.assets_detail.toPlainText()
    assert '1.2.3.4' in text
    assert 'AS13335' in text          # attrs rendered
    assert 'Исчез' in text            # GONE label


# ── F-K3: correlated findings in the detail panel ─────────────────────────────

def test_query_assets_table_includes_asset_findings(qapp):
    from core.asset_adapter import Asset, asset_fingerprint
    from core.asset_store import AssetStore
    from core.finding_fingerprint import scoped_id
    from core.findings_store import FindingsStore
    AssetStore().sync('pk', 's1', [Asset('endpoint', 'api.acme.com/graphql')])
    FindingsStore().upsert('pk', {
        'id': 'f-x', 'category': 'graphql', 'rule_id': 'i',
        'title': 'GraphQL introspection', 'severity': 'high',
        'evidence': {'location': 'api.acme.com/graphql'}})
    out = AssetsTabMixin._query_assets_table('pk', None, None)
    ep_id = scoped_id('pk', asset_fingerprint('endpoint', 'api.acme.com/graphql'))
    assert out['asset_findings'][ep_id]['worst'] == 'high'


def test_asset_detail_shows_correlated_findings(qapp):
    w = _window(qapp)
    w._assets_asset_findings = {'a1': {
        'findings': [{'severity': 'high', 'title': 'GraphQL introspection'}],
        'severity_counts': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0,
                            'info': 0}, 'worst': 'high'}}
    w._show_asset_detail({'id': 'a1', 'type': 'endpoint',
                          'value': 'api.acme.com/graphql',
                          'label': 'api.acme.com/graphql', 'status': 'ACTIVE'})
    text = w.assets_detail.toPlainText()
    assert 'Связанные находки: 1' in text
    assert 'GraphQL introspection' in text
