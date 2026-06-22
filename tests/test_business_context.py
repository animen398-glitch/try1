"""Business Context Model (EPIC NEXT F1).

User-declared asset importance (criticality + data sensitivity) stored as a single
additive ``business_context`` key in the project's metadata.json (project default +
per-asset overrides), feeding ``asset_criticality`` as extra named factors. Pure /
offline. No network.
"""

from core import business_context as bc
from core.asset_adapter import asset_fingerprint
from core.intelligence import build_asset_criticality
from core.project import Project, ProjectStore


# ── vocabulary / normalization ────────────────────────────────────────────────

def test_normalize_vocab():
    assert bc.normalize_criticality('HIGH') == 'high'
    assert bc.normalize_criticality('bogus') is None
    assert bc.normalize_data_sensitivity(' Confidential ') == 'confidential'
    assert bc.normalize_data_sensitivity('') is None


def test_normalize_context_keeps_only_valid():
    assert bc.normalize_context({'criticality': 'high', 'data_sensitivity': 'x'}) \
        == {'criticality': 'high'}
    assert bc.normalize_context('garbage') == {}


def test_normalize_root_drops_empties_and_garbage():
    root = bc.normalize_root({'default': {'criticality': 'high'},
                              'assets': {'fp1': {'criticality': 'low'},
                                         'fp2': {'criticality': 'nope'},
                                         '': {'criticality': 'high'}}})
    assert root == {'default': {'criticality': 'high'},
                    'assets': {'fp1': {'criticality': 'low'}}}
    assert bc.normalize_root('garbage') == {}
    assert bc.normalize_root({'default': {}, 'assets': {}}) == {}


# ── edit helpers + resolution ─────────────────────────────────────────────────

def test_set_and_clear_default():
    root = bc.set_default({}, {'criticality': 'high'})
    assert root == {'default': {'criticality': 'high'}}
    assert bc.set_default(root, {}) == {}            # empty clears


def test_set_and_clear_asset_override():
    root = bc.set_asset({}, 'fp1', {'data_sensitivity': 'restricted'})
    assert root == {'assets': {'fp1': {'data_sensitivity': 'restricted'}}}
    assert bc.set_asset(root, 'fp1', {}) == {}       # empty clears the override


def test_resolve_override_wins_per_field():
    root = {'default': {'criticality': 'medium', 'data_sensitivity': 'internal'},
            'assets': {'fp1': {'criticality': 'critical'}}}
    # fp1: criticality from override, data_sensitivity falls back to default.
    assert bc.resolve(root, 'fp1') == {'criticality': 'critical',
                                       'data_sensitivity': 'internal'}
    # unknown asset → the project default.
    assert bc.resolve(root, 'other') == {'criticality': 'medium',
                                         'data_sensitivity': 'internal'}
    assert bc.resolve({}, 'fp1') == {}


# ── weight / factors ──────────────────────────────────────────────────────────

def test_business_weight_and_factors():
    ctx = {'criticality': 'critical', 'data_sensitivity': 'restricted'}
    assert bc.business_weight(ctx) == 30 + 20
    factors = bc.business_factors(ctx)
    assert [f['points'] for f in factors] == [30, 20]
    assert bc.business_weight({}) == 0 and bc.business_factors({}) == []
    # 'low' / 'public' carry no weight → no factor.
    assert bc.business_factors({'criticality': 'low', 'data_sensitivity': 'public'}) == []


# ── Project metadata round-trip (RMW, composes with other keys) ───────────────

def test_project_get_set_business_context(tmp_path):
    project = Project(tmp_path / 'site.com', url='https://site.com').ensure()
    assert project.get_business_context() == {}

    project.set_company('acme')                      # an unrelated metadata key
    project.set_business_context({'default': {'criticality': 'high'}})
    assert project.get_business_context() == {'default': {'criticality': 'high'}}
    assert project.get_company() == 'acme'           # RMW preserved the other key

    project.set_business_context(None)               # clear
    assert project.get_business_context() == {}
    assert 'business_context' not in project.load_metadata()
    assert project.get_company() == 'acme'


# ── ProjectStore.resolve (shared target resolver) ─────────────────────────────

def test_projectstore_resolve(tmp_path):
    store = ProjectStore(tmp_path)
    created = store.resolve('https://site.com', create=True)
    assert created.slug == 'site.com'
    assert store.resolve('site.com').slug == 'site.com'   # by slug, no create
    import pytest
    with pytest.raises(KeyError):
        store.resolve('missing.com')


# ── derive: business augments asset_criticality ───────────────────────────────

def _asset(atype, value):
    return {'id': f'{atype}:{value}', 'type': atype, 'value': value, 'attrs': {}}


def test_build_asset_criticality_without_business_unchanged():
    assets = [_asset('subdomain', 'a.site.com')]
    base = build_asset_criticality(assets)
    assert build_asset_criticality(assets, business=None) == base
    assert build_asset_criticality(assets, business={}) == base   # empty == none


def test_build_asset_criticality_business_boosts_and_explains():
    assets = [_asset('subdomain', 'a.site.com')]
    base = build_asset_criticality(assets)['items'][0]['criticality']

    root = {'default': {'criticality': 'critical'}}   # +30 to every asset
    boosted = build_asset_criticality(assets, business=root)['items'][0]
    assert boosted['criticality'] == base + 30
    assert any('Бизнес-критичность' in f['factor'] for f in boosted['factors'])


def test_build_asset_criticality_per_asset_override_only_targets_one():
    assets = [_asset('subdomain', 'a.site.com'), _asset('subdomain', 'b.site.com')]
    fp_a = asset_fingerprint('subdomain', 'a.site.com')
    root = {'assets': {fp_a: {'criticality': 'critical'}}}
    items = {i['value']: i['criticality']
             for i in build_asset_criticality(assets, business=root)['items']}
    plain = {i['value']: i['criticality']
             for i in build_asset_criticality(assets)['items']}
    assert items['a.site.com'] == plain['a.site.com'] + 30
    assert items['b.site.com'] == plain['b.site.com']   # untouched


# ── management helpers (CLI / web layer) ──────────────────────────────────────

def test_management_set_show_clear(tmp_path):
    store = ProjectStore(tmp_path)
    res = bc.set_business_context(store, 'site.com', criticality='high',
                                  data_sensitivity='confidential')
    assert res['business_context']['default'] == {'criticality': 'high',
                                                  'data_sensitivity': 'confidential'}

    fp = asset_fingerprint('subdomain', 'api.site.com')
    bc.set_business_context(store, 'site.com', asset_fp=fp, criticality='critical')
    shown = bc.show_business_context(store, 'site.com')
    assert shown['business_context']['assets'][fp] == {'criticality': 'critical'}

    bc.clear_business_context(store, 'site.com', asset_fp=fp)
    assert not bc.show_business_context(store, 'site.com')['business_context'].get('assets')
    bc.clear_business_context(store, 'site.com')
    assert bc.show_business_context(store, 'site.com')['business_context'] == {}


# ── CLI smoke ─────────────────────────────────────────────────────────────────

def test_cli_set_show_clear(tmp_path):
    import business_cli
    base = ['--output', str(tmp_path)]
    assert business_cli.main(base + ['set', 'site.com', '--criticality', 'high']) == 0
    assert ProjectStore(tmp_path).get('site.com').get_business_context() \
        == {'default': {'criticality': 'high'}}
    assert business_cli.main(base + ['show', 'site.com']) == 0
    assert business_cli.main(base + ['clear', 'site.com']) == 0
    assert ProjectStore(tmp_path).get('site.com').get_business_context() == {}


# ── web read-parity (_criticality_view folds in business) ─────────────────────

def test_web_criticality_view_uses_business(tmp_path, monkeypatch):
    from core.asset_store import AssetStore
    from core.asset_adapter import Asset
    import remote.web_app as web

    store = ProjectStore(tmp_path)
    project = store.resolve('site.com', create=True)
    project.set_business_context({'default': {'criticality': 'critical'}})
    AssetStore().upsert('site.com', Asset(type='subdomain',
                                          value='a.site.com').to_store(), scan_id='s1')

    monkeypatch.setattr(web, '_REPORT_BASE', tmp_path)
    view = web._criticality_view('site.com')
    item = view['items'][0]
    assert any('Бизнес-критичность' in f['factor'] for f in item['factors'])
