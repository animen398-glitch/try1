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


# ── F-A1: richer attrs (TLS / probe / provider) folded from existing report ───

def _attrs_for(assets, atype, value):
    for a in assets:
        if a.type == atype and a.value == value:
            return a.attrs
    raise AssertionError(f'no {atype} asset {value!r}')


def test_split_sans_cleans_and_dedups():
    assert aa._split_sans('DNS:example.com, dns:*.example.com, example.com') == [
        'example.com', '*.example.com']
    assert aa._split_sans(['a.com.', 'A.com']) == ['a.com']
    assert aa._split_sans('') == []


def test_domain_carries_tls_and_provider_attrs():
    r = _report()
    r['phases']['certificate'] = {'status': 'Success', 'data': {
        'issuer': "Let's Encrypt", 'subject': 'example.com',
        'not_after': '2026-09-01', 'sans': 'DNS:example.com, DNS:api.example.com'}}
    r['phases']['recon']['data']['infrastructure']['location'] = 'San Francisco, US'
    attrs = _attrs_for(aa.derive_assets(r), 'domain', 'example.com')
    assert attrs['tls_issuer'] == "Let's Encrypt"
    assert attrs['tls_not_after'] == '2026-09-01'
    assert attrs['tls_sans'] == ['example.com', 'api.example.com']
    assert attrs['provider'] == 'Cloudflare'
    assert attrs['location'] == 'San Francisco, US'


def test_subdomain_carries_probe_attrs_and_drops_empty():
    r = _report()
    r['phases']['subdomains']['data']['results'] = [
        {'subdomain': 'api.example.com', 'ip': '1.2.3.5', 'cname': 'cdn.fastly.net',
         'service': 'Fastly', 'takeover': True, 'http_status': 200,
         'server': 'nginx', 'title': '', 'status': 'HTTP 200'},
        {'subdomain': 'dead.example.com', 'ip': '', 'takeover': False},
    ]
    assets = aa.derive_assets(r)
    api = _attrs_for(assets, 'subdomain', 'api.example.com')
    assert api['service'] == 'Fastly' and api['cname'] == 'cdn.fastly.net'
    assert api['takeover'] is True and api['server'] == 'nginx'
    assert 'title' not in api                      # empty dropped
    dead = _attrs_for(assets, 'subdomain', 'dead.example.com')
    assert 'takeover' not in dead                  # False dropped (only flag when True)
    assert 'http_status' not in dead


def test_ip_and_asn_carry_provider_location():
    r = _report()
    r['phases']['recon']['data']['infrastructure'].update(
        {'org': 'Cloudflare, Inc.', 'location': 'US'})
    assets = aa.derive_assets(r)
    assert _attrs_for(assets, 'ip', '1.2.3.4')['provider'] == 'Cloudflare'
    assert _attrs_for(assets, 'ip', '1.2.3.4')['location'] == 'US'
    asn = _attrs_for(assets, 'asn', 'as13335')
    assert asn['org'] == 'Cloudflare, Inc.' and asn['location'] == 'US'


def test_enrichment_does_not_change_identity():
    # Attrs are non-identity: a richer report yields the SAME asset ids.
    plain = {a.type: a.id for a in aa.derive_assets(_report())}
    r = _report()
    r['phases']['certificate'] = {'data': {'issuer': 'X', 'sans': 'DNS:y.com'}}
    r['phases']['subdomains']['data']['results'][0]['service'] = 'Fastly'
    rich = {a.type: a.id for a in aa.derive_assets(r)}
    assert plain == rich
