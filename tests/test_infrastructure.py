"""ASN & infrastructure intelligence — chain build + offline render."""

from core import infrastructure as infra


# ── parse_as_field ──────────────────────────────────────────────────────────

def test_parse_as_field_splits_number_and_name():
    assert infra.parse_as_field('AS13335 Cloudflare, Inc.') == (
        'AS13335', 'Cloudflare, Inc.')


def test_parse_as_field_number_only():
    assert infra.parse_as_field('AS15169') == ('AS15169', '')


def test_parse_as_field_empty():
    assert infra.parse_as_field('') == (None, '')
    assert infra.parse_as_field('not-an-asn') == (None, '')


# ── build_infrastructure ────────────────────────────────────────────────────

def _recon(**geo):
    return {'domain': 'ex.com', 'ip': '1.2.3.4', 'geo': geo}


def test_build_infrastructure_full_chain():
    out = infra.build_infrastructure(_recon(
        **{'as': 'AS13335 Cloudflare, Inc.', 'org': 'Cloudflare',
           'isp': 'Cloudflare', 'city': 'SF', 'regionName': 'CA',
           'country': 'US'}))
    assert out['asn'] == 'AS13335'
    assert out['asn_name'] == 'Cloudflare, Inc.'
    assert out['provider'] == 'Cloudflare'
    assert out['location'] == 'SF, CA, US'
    roles = [hop['role'] for hop in out['chain']]
    assert roles == ['Domain', 'ASN', 'IP', 'Provider']


def test_build_infrastructure_provider_fallback_to_asn_name():
    out = infra.build_infrastructure(_recon(**{'as': 'AS123 Acme Net'}))
    assert out['provider'] == 'Acme Net'   # no org/isp → asn_name


def test_build_infrastructure_provider_fallback_to_isp():
    out = infra.build_infrastructure(_recon(isp='Some ISP'))
    assert out['provider'] == 'Some ISP'   # no as/org → isp


def test_build_infrastructure_partial_no_geo():
    out = infra.build_infrastructure({'domain': 'ex.com', 'ip': '1.2.3.4'})
    roles = [hop['role'] for hop in out['chain']]
    assert roles == ['Domain', 'IP']       # no ASN/provider hops invented
    assert out['asn'] is None


def test_build_infrastructure_empty():
    out = infra.build_infrastructure({})
    assert out['chain'] == []


# ── render_html (offline) ───────────────────────────────────────────────────

def test_render_html_offline_chain():
    out = infra.render_html(infra.build_infrastructure(_recon(
        **{'as': 'AS13335 Cloudflare', 'org': 'Cloudflare'})))
    assert '<script' not in out.lower()
    assert 'AS13335' in out
    assert 'Cloudflare' in out
    assert '→' in out                      # chain arrows between hops


def test_render_html_escapes():
    out = infra.render_html({'chain': [
        {'role': 'Domain', 'value': '<x>'}]})
    assert '&lt;x&gt;' in out


def test_render_html_empty_placeholder():
    out = infra.render_html({'chain': []})
    assert 'Недостаточно данных' in out
    assert infra.render_html(None)         # tolerates None
