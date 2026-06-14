"""Asset identity + derivation (core/asset_adapter.py) — pure, offline."""

import hashlib

from core import asset_adapter as aa


# ── identity / normalization ──────────────────────────────────────────────────

def test_fingerprint_matches_formula_and_normalizes():
    # Locks the algorithm AND the normalization (lower + strip trailing dot).
    expected = hashlib.sha1('subdomain\x1fapi.example.com'.encode()).hexdigest()
    assert aa.asset_fingerprint('subdomain', 'API.example.com.') == expected
    assert len(expected) == 40


def test_fingerprint_is_deterministic_and_type_scoped():
    a = aa.asset_fingerprint('ip', '1.2.3.4')
    assert a == aa.asset_fingerprint('ip', '1.2.3.4')
    # Same value, different type → different identity.
    assert a != aa.asset_fingerprint('netblock', '1.2.3.4')


def test_endpoint_identity_ignores_query_and_scheme():
    a = aa.asset_fingerprint('endpoint', 'https://x.com/a?b=1#f')
    b = aa.asset_fingerprint('endpoint', 'http://x.com/a')
    assert a == b


def test_technology_identity_is_name_not_version():
    # A version bump is a change of one asset, not a new asset.
    assert (aa.Asset('technology', 'Nginx', attrs={'version': '1.25'}).id
            == aa.Asset('technology', 'Nginx', attrs={'version': '1.27'}).id)


def test_asset_to_store_shape():
    s = aa.Asset('subdomain', 'API.x.com', attrs={'ip': '1.1.1.1'}).to_store()
    assert s['type'] == 'subdomain'
    assert s['value'] == 'api.x.com'          # normalized
    assert s['label'] == 'API.x.com'          # display preserves original
    assert s['attrs'] == {'ip': '1.1.1.1'}
    assert len(s['id']) == 40


# ── derive_assets ─────────────────────────────────────────────────────────────

def _report():
    return {
        'url': 'https://example.com', 'domain': 'example.com',
        'phases': {
            'recon': {'status': 'Success', 'data': {
                'ip': '1.2.3.4', 'cms': ['WordPress'],
                'technologies': [{'name': 'Nginx', 'category': 'Server',
                                  'version': '1.25'}],
                'infrastructure': {'asn': 'AS13335', 'asn_name': 'Cloudflare',
                                   'ip': '1.2.3.4', 'provider': 'Cloudflare'}}},
            'subdomains': {'status': 'Success', 'data': {'results': [
                {'subdomain': 'api.example.com', 'ip': '1.2.3.5'}]}},
            'asn_intel': {'status': 'Success', 'data': {
                'cidr': '1.2.0.0/16', 'prefixes': ['1.2.0.0/16', '1.3.0.0/16']}},
            'katana': {'status': 'Success', 'data': {
                'endpoints': ['https://example.com/login']}},
            'openapi': {'status': 'Success', 'data': {'endpoints': [
                {'method': 'GET', 'path': '/api/v1/users'}]}},
        },
    }


def _by_type(assets):
    out = {}
    for a in assets:
        out.setdefault(a.type, []).append(a.value)
    return out


def test_derive_covers_every_type():
    bt = _by_type(aa.derive_assets(_report()))
    assert bt['domain'] == ['example.com']
    assert bt['subdomain'] == ['api.example.com']
    assert bt['ip'] == ['1.2.3.4']                       # recon+infra deduped
    assert bt['asn'] == ['as13335']                      # normalized lower
    assert set(bt['netblock']) == {'1.2.0.0/16', '1.3.0.0/16'}  # cidr∪prefix deduped
    assert set(bt['technology']) == {'nginx', 'wordpress'}
    assert any('login' in e for e in bt['endpoint'])
    assert any('users' in e for e in bt['endpoint'])


def test_derive_dedups_by_identity():
    assets = aa.derive_assets(_report())
    ids = [a.id for a in assets]
    assert len(ids) == len(set(ids))


def test_derive_tolerates_empty_and_partial():
    assert aa.derive_assets({}) == []
    assert aa.derive_assets({'phases': {}}) == []
    # Only a domain when nothing else ran.
    only = aa.derive_assets({'url': 'https://x.com', 'phases': {}})
    assert [a.type for a in only] == ['domain'] and only[0].value == 'x.com'


def test_source_phases_map_covers_all_types():
    for t in aa.ASSET_TYPES:
        assert t in aa.ASSET_SOURCE_PHASES
