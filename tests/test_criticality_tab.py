"""Asset Criticality GUI tab (gui/tab_criticality.py) — headless.

Mirrors test_intelligence_tab / test_assets_tab: off-GUI queries are plain
staticmethods exercised directly, and populate/selection logic is driven with
``_run_async`` stubbed out. The assets DB is the per-test temp file from conftest's
``_isolate_assets_db`` fixture, so ``AssetStore()`` inside the tab and inside the
test share one store. Criticality is per-project, display-only and read-only.
"""

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from gui.plugin_manager import default_manager
from gui.tab_criticality import CriticalityTabMixin
from tests.gui_test_helpers import CriticalityHost


def _window(qapp):
    return CriticalityHost()


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
    titles = [p.title for p in default_manager()]
    assert 'Asset Criticality' in titles


# ── off-GUI queries read the store ─────────────────────────────────────────────

def test_query_projects_lists_asset_projects(qapp):
    _seed()
    res = CriticalityTabMixin._query_crit_projects()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 2
    assert by_name['p2']['total'] == 1


def test_query_table_ranks_by_criticality(qapp, tmp_path):
    _seed()
    out = CriticalityTabMixin._query_crit_table('p1', str(tmp_path))
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

def test_table_load_error_clears_stale_rows_rollup_and_business(qapp):
    w = _window(qapp)
    w._on_crit_table_loaded({'project': 'p1', 'crit': {
        'items': [{'id': 'a-1', 'fp': 'fp-1', 'type': 'domain', 'value': 'x.com',
                   'criticality': 65, 'band': 'medium', 'factors': []}],
        'summary': {'assets': 1, 'high_criticality': 0, 'top_criticality': 65},
    }, 'business': {'default': {'criticality': 'high'}}})
    w.crit_table.selectRow(0)
    assert w.crit_table.rowCount() == 1

    w._on_crit_table_loaded({'project': 'p1', 'error': 'boom'})

    assert w.crit_table.rowCount() == 0
    assert w.crit_detail.toPlainText() == ''
    assert w.crit_rollup['assets'].text() == '0'
    assert w._crit_records == []
    assert w._crit_business == {}
    assert w.biz_default_crit.currentData() == ''
    assert 'boom' in w.crit_status.text()


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


# ── business context editor (F1 GUI) ────────────────────────────────────────────

def test_biz_combo_has_unset_and_options(qapp):
    w = _window(qapp)
    datas = [w.biz_default_crit.itemData(i)
             for i in range(w.biz_default_crit.count())]
    assert datas[0] == ''                 # leading unset entry
    assert 'critical' in datas and 'low' in datas


def test_populate_biz_default_reflects_stored(qapp):
    w = _window(qapp)
    w._populate_biz_default({'default': {'criticality': 'high',
                                         'data_sensitivity': 'confidential'}})
    assert w.biz_default_crit.currentData() == 'high'
    assert w.biz_default_sens.currentData() == 'confidential'
    w._populate_biz_default({})            # unset → back to '—'
    assert w.biz_default_crit.currentData() == ''


def test_write_business_persists_and_boosts_criticality(qapp, tmp_path):
    s = AssetStore()
    s.sync('shop.com', 's1', [Asset('subdomain', 'a.shop.com')])
    base = str(tmp_path)
    before = CriticalityTabMixin._query_crit_table(
        'shop.com', base)['crit']['items'][0]['criticality']
    res = CriticalityTabMixin._write_business(base, 'shop.com', 'critical',
                                              'restricted')
    assert res.get('ok')
    out = CriticalityTabMixin._query_crit_table('shop.com', base)
    assert out['business']['default'] == {'criticality': 'critical',
                                          'data_sensitivity': 'restricted'}
    assert out['crit']['items'][0]['criticality'] > before   # business augmented


def test_apply_business_default_writes_metadata(qapp, tmp_path):
    from core.project import ProjectStore
    w = _window(qapp)
    w.settings['output_dir'] = str(tmp_path)
    w.crit_project.addItem('shop.com', 'shop.com')
    w.crit_project.setCurrentIndex(w.crit_project.count() - 1)
    w.biz_default_crit.setCurrentIndex(w.biz_default_crit.findData('high'))
    w._set_busy = lambda *a, **k: None
    w._apply_crit_filter = lambda *a, **k: None        # skip the reload chain
    w._run_async = lambda work, cb: cb(work())         # run synchronously
    w._apply_business_default()
    proj = ProjectStore(str(tmp_path)).get('shop.com')
    assert proj.get_business_context()['default'] == {'criticality': 'high'}


# ── per-asset business override editor (F1 GUI tail) ─────────────────────────────

def test_items_carry_business_fingerprint(qapp, tmp_path):
    # Each criticality item exposes the bare fingerprint the override keys on.
    from core.asset_adapter import asset_fingerprint
    AssetStore().sync('p1', 's1', [Asset('domain', 'x.com')])
    items = CriticalityTabMixin._query_crit_table('p1', str(tmp_path))['crit']['items']
    assert items[0]['fp'] == asset_fingerprint('domain', 'x.com')


def test_asset_editor_disabled_until_selection(qapp):
    w = _window(qapp)
    w._populate_biz_asset(None)
    assert not w.biz_asset_crit.isEnabled()
    assert not w.biz_asset_apply.isEnabled()


def test_populate_biz_asset_reflects_override_and_resolved(qapp):
    w = _window(qapp)
    w._crit_business = {'default': {'criticality': 'low'},
                        'assets': {'fp-1': {'criticality': 'critical',
                                            'data_sensitivity': 'restricted'}}}
    w._populate_biz_asset({'fp': 'fp-1', 'type': 'domain', 'value': 'x.com'})
    assert w.biz_asset_crit.currentData() == 'critical'      # override, not default
    assert w.biz_asset_sens.currentData() == 'restricted'
    assert w.biz_asset_apply.isEnabled()
    # resolved = default + override, override wins field-by-field.
    assert 'Строго конфиденциально' in w.biz_asset_label.text()


def test_apply_business_asset_writes_override(qapp, tmp_path):
    from core.asset_adapter import asset_fingerprint
    from core.project import ProjectStore
    AssetStore().sync('shop.com', 's1', [Asset('subdomain', 'a.shop.com')])
    fp = asset_fingerprint('subdomain', 'a.shop.com')
    w = _window(qapp)
    w.settings['output_dir'] = str(tmp_path)
    w.crit_project.addItem('shop.com', 'shop.com')
    w.crit_project.setCurrentIndex(w.crit_project.count() - 1)
    w._populate_crit_table([{'fp': fp, 'id': 'a-1', 'type': 'subdomain',
                             'value': 'a.shop.com', 'criticality': 30,
                             'band': 'low', 'factors': []}])
    w.crit_table.selectRow(0)
    w.biz_asset_crit.setCurrentIndex(w.biz_asset_crit.findData('critical'))
    w._set_busy = lambda *a, **k: None
    w._apply_crit_filter = lambda *a, **k: None        # skip the reload chain
    w._run_async = lambda work, cb: cb(work())         # run synchronously
    w._apply_business_asset()
    ctx = ProjectStore(str(tmp_path)).get('shop.com').get_business_context()
    assert ctx['assets'][fp] == {'criticality': 'critical'}
    assert w._crit_reselect_fp == fp                   # selection preserved on reload


def test_clear_business_asset_removes_override(qapp, tmp_path):
    from core.asset_adapter import asset_fingerprint
    from core.business_context import set_business_context
    from core.project import ProjectStore
    AssetStore().sync('shop.com', 's1', [Asset('subdomain', 'a.shop.com')])
    fp = asset_fingerprint('subdomain', 'a.shop.com')
    store = ProjectStore(str(tmp_path))
    set_business_context(store, 'shop.com', asset_fp=fp, criticality='high')
    w = _window(qapp)
    w.settings['output_dir'] = str(tmp_path)
    w.crit_project.addItem('shop.com', 'shop.com')
    w.crit_project.setCurrentIndex(w.crit_project.count() - 1)
    w._populate_crit_table([{'fp': fp, 'id': 'a-1', 'type': 'subdomain',
                             'value': 'a.shop.com', 'criticality': 50,
                             'band': 'low', 'factors': []}])
    w.crit_table.selectRow(0)
    w._set_busy = lambda *a, **k: None
    w._apply_crit_filter = lambda *a, **k: None
    w._run_async = lambda work, cb: cb(work())
    w._clear_business_asset()
    ctx = store.get('shop.com').get_business_context()
    assert fp not in (ctx.get('assets') or {})
