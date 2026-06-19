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


def test_security_audit_endpoints_become_assets():
    # URLs the deep-JS audit extracted become endpoint assets gated on the
    # security phase (so a skipped audit doesn't mark them gone).
    r = {'url': 'https://x.com', 'phases': {
        'security': {'status': 'Success', 'data': {'endpoints': [
            {'url': 'https://x.com/api/hidden', 'found_in': 'https://x.com/app.js'}]}}}}
    bt = _by_type(aa.derive_assets(r))
    assert any('api/hidden' in e for e in bt['endpoint'])
    attrs = _attrs_for(aa.derive_assets(r), 'endpoint',
                       aa._normalize_value('endpoint', 'https://x.com/api/hidden'))
    assert attrs['source'] == 'security'


def test_endpoint_shared_by_katana_and_audit_keeps_katana_source():
    # An endpoint found by both keeps Katana's source (derive is first-wins), so
    # its GONE gating stays on the always-available crawl, not the opt-in audit.
    r = {'url': 'https://x.com', 'phases': {
        'katana': {'status': 'Success', 'data': {'endpoints': ['https://x.com/api']}},
        'security': {'status': 'Success', 'data': {'endpoints': [
            {'url': 'https://x.com/api', 'found_in': 'js'}]}}}}
    attrs = _attrs_for(aa.derive_assets(r), 'endpoint',
                       aa._normalize_value('endpoint', 'https://x.com/api'))
    assert attrs['source'] == 'katana'


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


def test_cert_sans_promoted_to_subdomain_assets():
    r = _report()
    r['phases']['subdomains']['data']['results'] = []        # no active probe
    r['phases']['certificate'] = {'status': 'Success', 'data': {
        'sans': 'DNS:example.com, DNS:mail.example.com, DNS:*.example.com'}}
    bt = _by_type(aa.derive_assets(r))
    # apex + wildcard excluded; only the concrete SAN host promoted.
    assert bt['subdomain'] == ['mail.example.com']
    src = _attrs_for(aa.derive_assets(r), 'subdomain', 'mail.example.com')['source']
    assert src == 'certificate'


def test_ct_names_promoted_to_subdomain_assets():
    r = _report()
    r['phases']['subdomains']['data']['results'] = []
    r['phases']['ct'] = {'status': 'Success', 'data': {
        'names': ['example.com', 'vpn.example.com', '*.example.com']}}
    assets = aa.derive_assets(r)
    bt = _by_type(assets)
    assert bt['subdomain'] == ['vpn.example.com']            # apex/wildcard dropped
    assert _attrs_for(assets, 'subdomain', 'vpn.example.com')['source'] == 'ct'


def test_active_probe_wins_subdomain_identity_over_cert():
    # A name found by BOTH the active probe and the certificate is one asset,
    # keeping the richer probe attrs (first occurrence wins the identity).
    r = _report()
    r['phases']['subdomains']['data']['results'] = [
        {'subdomain': 'api.example.com', 'ip': '1.2.3.5', 'service': 'Fastly'}]
    r['phases']['certificate'] = {'status': 'Success', 'data': {
        'sans': 'DNS:api.example.com'}}
    subs = [a for a in aa.derive_assets(r) if a.type == 'subdomain']
    assert [a.value for a in subs] == ['api.example.com']    # one asset, not two
    assert subs[0].attrs['source'] == 'subdomains'           # probe kept
    assert subs[0].attrs['service'] == 'Fastly'


def test_ip_and_asn_carry_provider_location():
    r = _report()
    r['phases']['recon']['data']['infrastructure'].update(
        {'org': 'Cloudflare, Inc.', 'location': 'US'})
    assets = aa.derive_assets(r)
    assert _attrs_for(assets, 'ip', '1.2.3.4')['provider'] == 'Cloudflare'
    assert _attrs_for(assets, 'ip', '1.2.3.4')['location'] == 'US'
    asn = _attrs_for(assets, 'asn', 'as13335')
    assert asn['org'] == 'Cloudflare, Inc.' and asn['location'] == 'US'


def test_domain_ip_asn_carry_cloud_and_region_attrs():
    # build_infrastructure now derives cloud/region; the adapter folds them into
    # the host/infra asset attrs (additive, non-identity).
    r = _report()
    r['phases']['recon']['data']['infrastructure'].update(
        {'cloud': 'AWS', 'region': 'Virginia'})
    assets = aa.derive_assets(r)
    dom = _attrs_for(assets, 'domain', 'example.com')
    assert dom['cloud'] == 'AWS' and dom['region'] == 'Virginia'
    assert _attrs_for(assets, 'ip', '1.2.3.4')['cloud'] == 'AWS'
    assert _attrs_for(assets, 'asn', 'as13335')['cloud'] == 'AWS'


def test_subdomain_cloud_from_cname():
    # A subdomain's hosting cloud is classified from its CNAME (per-host signal).
    r = _report()
    r['phases']['subdomains']['data']['results'] = [
        {'subdomain': 'app.example.com', 'cname': 'app.azurewebsites.net'}]
    attrs = _attrs_for(aa.derive_assets(r), 'subdomain', 'app.example.com')
    assert attrs['cloud'] == 'Microsoft Azure'


def test_subdomain_no_cloud_without_cname_signal():
    r = _report()
    r['phases']['subdomains']['data']['results'] = [
        {'subdomain': 'plain.example.com', 'ip': '1.2.3.5'}]
    attrs = _attrs_for(aa.derive_assets(r), 'subdomain', 'plain.example.com')
    assert 'cloud' not in attrs                       # no CNAME signal → no guess


def test_cloud_region_attrs_do_not_change_identity():
    # cloud/region are attrs, not identity — enriching them yields the SAME ids.
    plain = {a.type: a.id for a in aa.derive_assets(_report())}
    r = _report()
    r['phases']['recon']['data']['infrastructure'].update(
        {'cloud': 'AWS', 'region': 'Virginia'})
    r['phases']['subdomains']['data']['results'][0]['cname'] = 'x.azurewebsites.net'
    rich = {a.type: a.id for a in aa.derive_assets(r)}
    for t, i in plain.items():
        assert rich.get(t) == i


def test_enrichment_does_not_change_identity():
    # Attrs are non-identity: a richer report yields the SAME asset ids.
    plain = {a.type: a.id for a in aa.derive_assets(_report())}
    r = _report()
    r['phases']['certificate'] = {'data': {'issuer': 'X', 'sans': 'DNS:y.com'}}
    r['phases']['subdomains']['data']['results'][0]['service'] = 'Fastly'
    rich = {a.type: a.id for a in aa.derive_assets(r)}
    assert plain == rich
