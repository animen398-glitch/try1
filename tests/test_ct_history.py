"""Tests for Certificate Transparency History (core/ct_history.py, #13 OSINT).

Parsing and analysis are pure; ``now`` and the crt.sh fetch are injected so the
suite is network-free and time-deterministic.
"""

from datetime import datetime

from core import ct_history as ct, scan_diff

# A fixed "now" so recent/active windows are deterministic.
NOW = datetime(2024, 6, 1)


def _entry(cid, names, issuer='C=US, O=Let\'s Encrypt, CN=R3',
           not_before='2024-05-01T00:00:00', not_after='2024-08-01T00:00:00'):
    return {'id': cid, 'issuer_name': issuer, 'name_value': names,
            'not_before': not_before, 'not_after': not_after}


# ── pure helpers ──────────────────────────────────────────────────────────────

def test_parse_dt_variants():
    assert ct._parse_dt('2024-05-01T00:00:00') == datetime(2024, 5, 1)
    assert ct._parse_dt('2024-05-01T12:34:56.789').year == 2024   # fractional
    assert ct._parse_dt('2024-05-01 00:00:00Z') == datetime(2024, 5, 1)  # space+Z
    assert ct._parse_dt('') is None and ct._parse_dt('nope') is None


def test_issuer_label_prefers_org():
    assert ct._issuer_label("C=US, O=Let's Encrypt, CN=R3") == "Let's Encrypt"
    assert ct._issuer_label('CN=Some CA') == 'Some CA'
    assert ct._issuer_label('') == '—'


def test_in_domain_names_filters_and_flags_wildcard():
    names, wild = ct._in_domain_names('*.x.com\napi.x.com\nevil.com', 'x.com')
    assert names == {'x.com', 'api.x.com'} and wild is True


# ── analyze (pure, injected now) ──────────────────────────────────────────────

def test_analyze_aggregates_history():
    entries = [
        _entry(1, 'x.com\nwww.x.com'),
        _entry(2, '*.x.com', issuer='C=US, O=DigiCert Inc, CN=DigiCert',
               not_before='2020-01-01T00:00:00', not_after='2021-01-01T00:00:00'),
        _entry(1, 'x.com'),                       # duplicate id → ignored
        _entry(3, 'only.evil.com'),               # off-domain → dropped
    ]
    out = ct.analyze(entries, 'x.com', now=NOW)
    assert out['total_certs'] == 2
    assert out['name_count'] == 2                 # x.com, www.x.com
    assert out['names'] == ['www.x.com', 'x.com']
    assert out['wildcards'] == ['x.com']
    assert {i['ca'] for i in out['issuers']} == {"Let's Encrypt", 'DigiCert Inc'}
    assert out['first_seen'][:4] == '2020' and out['last_seen'][:4] == '2024'
    assert out['recent_count'] == 1               # only cert 1 within 90d of NOW
    assert out['active_count'] == 1 and out['expired_count'] == 1


def test_analyze_empty():
    out = ct.analyze([], 'x.com', now=NOW)
    assert out['total_certs'] == 0 and out['certs'] == []


def test_analyze_cert_list_is_recent_first_and_clean():
    entries = [_entry(1, 'a.x.com', not_before='2022-01-01T00:00:00'),
               _entry(2, 'b.x.com', not_before='2024-05-01T00:00:00')]
    out = ct.analyze(entries, 'x.com', now=NOW)
    assert [c['id'] for c in out['certs']] == [2, 1]      # newest first
    assert all(not k.startswith('_') for c in out['certs'] for k in c)  # no _nb/_na


# ── discover (injected fetch) ─────────────────────────────────────────────────

def test_discover_success_strips_www():
    out = ct.discover('https://www.x.com', now=NOW,
                      fetch=lambda d: [_entry(1, 'x.com')])
    assert out['status'] == 'Success' and out['domain'] == 'x.com'
    assert out['total_certs'] == 1


def test_discover_no_certificates():
    out = ct.discover('https://x.com', now=NOW, fetch=lambda d: [])
    assert out['status'] == 'No certificates' and out['total_certs'] == 0


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline():
    out = ct.discover('https://x.com', now=NOW,
                      fetch=lambda d: [_entry(1, 'x.com\napi.x.com')])
    page = ct.render_html(out)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert 'Encrypt' in page and 'api.x.com' in page   # apostrophe is escaped


def test_render_html_no_certificates():
    assert 'не найдены' in ct.render_html({'status': 'No certificates'})


# ── integration: scan_diff ct section ─────────────────────────────────────────

def _report_with_certs(certs):
    return {'phases': {'ct': {'status': 'Success', 'data': {'certs': certs}}}}


def test_scan_diff_reports_new_certificate():
    a = _report_with_certs([{'id': 1, 'issuer': 'LE',
                             'not_before': '2024-01-01T00:00:00',
                             'names': ['x.com']}])
    b = _report_with_certs([
        {'id': 1, 'issuer': 'LE', 'not_before': '2024-01-01T00:00:00',
         'names': ['x.com']},
        {'id': 2, 'issuer': 'DigiCert', 'not_before': '2024-05-01T00:00:00',
         'names': ['new.x.com']}])
    d = scan_diff.diff(a, b)
    assert d['sections']['ct']['added'] == ['2024-05-01 · DigiCert: new.x.com']
