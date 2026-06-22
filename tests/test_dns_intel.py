"""Tests for DNS Intelligence (core/dns_intel.py, roadmap #13 OSINT).

Analysis is pure; DoH lookups are exercised with urlopen_text stubbed and
discover()/fetch_records with an injected query, so nothing hits the network.
"""

import json

from core import dns_intel as dns, scan_diff


def _records(**kw):
    base = {t: [] for t in dns.RECORD_TYPES}
    base['DMARC'] = []
    base['DKIM'] = {}
    base.update(kw)
    return base


# ── analyze (pure) ────────────────────────────────────────────────────────────

def test_analyze_healthy_domain_has_no_findings():
    rec = _records(
        A=['1.2.3.4'], MX=['10 mail.x.com.'],
        TXT=['v=spf1 include:_spf.google.com ~all'],
        DMARC=['v=DMARC1; p=reject; rua=mailto:a@x.com'],
        DKIM={'google': ['v=DKIM1; k=rsa; p=MIGf...']},
        CAA=['0 issue "letsencrypt.org"'])
    out = dns.analyze(rec)
    assert out['email_auth']['spf'].startswith('v=spf1')
    assert out['email_auth']['dmarc'] == 'reject'
    assert out['email_auth']['dkim_selectors'] == ['google']
    assert out['email_auth']['caa'] is True
    assert out['findings'] == []


def test_analyze_flags_missing_email_auth():
    out = dns.analyze(_records(A=['1.2.3.4']))
    titles = {f['title'] for f in out['findings']}
    assert 'No SPF record' in titles
    assert 'No DMARC record' in titles
    assert 'No DKIM selector found' in titles
    assert 'No CAA record' in titles
    # the two email-spoofing gaps are Medium
    sev = {f['title']: f['severity'] for f in out['findings']}
    assert sev['No SPF record'] == 'Medium' and sev['No DMARC record'] == 'Medium'


def test_analyze_weak_dmarc_is_info():
    out = dns.analyze(_records(
        TXT=['v=spf1 ~all'], DMARC=['v=DMARC1; p=none'],
        DKIM={'default': ['v=DKIM1']}, CAA=['0 issue "x"']))
    titles = {f['title']: f['severity'] for f in out['findings']}
    assert titles == {'DMARC policy is p=none': 'Info'}


def test_analyze_flags_pass_all_spf():
    # +all (and a bare all) pass every sender → a Medium misconfiguration finding.
    full = _records(TXT=['v=spf1 include:x +all'], DMARC=['v=DMARC1; p=reject'],
                    DKIM={'default': ['v=DKIM1']}, CAA=['0 issue "x"'])
    sev = {f['title']: f['severity'] for f in dns.analyze(full)['findings']}
    assert sev == {'SPF allows all senders (+all)': 'Medium'}
    # a bare "all" defaults to +all → same finding
    full['TXT'] = ['v=spf1 all']
    titles = {f['title'] for f in dns.analyze(full)['findings']}
    assert 'SPF allows all senders (+all)' in titles


def test_analyze_flags_neutral_spf_is_info():
    rec = _records(TXT=['v=spf1 ?all'], DMARC=['v=DMARC1; p=reject'],
                   DKIM={'default': ['v=DKIM1']}, CAA=['0 issue "x"'])
    sev = {f['title']: f['severity'] for f in dns.analyze(rec)['findings']}
    assert sev == {'SPF policy is neutral (?all)': 'Info'}


def test_analyze_flags_dmarc_partial_enforcement():
    # An enforcing policy undercut by pct<100 (partial) or sp=none (subdomains
    # unprotected) — both Info findings; pct=100 / no sp is clean.
    rec = _records(TXT=['v=spf1 -all'],
                   DMARC=['v=DMARC1; p=reject; pct=10; sp=none'],
                   DKIM={'default': ['v=DKIM1']}, CAA=['0 issue "x"'])
    titles = {f['title']: f['severity'] for f in dns.analyze(rec)['findings']}
    assert titles == {'DMARC partial enforcement (pct=10)': 'Info',
                      'DMARC subdomain policy is sp=none': 'Info'}
    # pct=100 and no sp → no DMARC finding.
    rec['DMARC'] = ['v=DMARC1; p=reject; pct=100']
    assert dns.analyze(rec)['findings'] == []


def test_dmarc_tags_and_policy_parsing():
    rec = _records(DMARC=['v=DMARC1; p=Quarantine; pct=50; sp=none'])
    tags = dns._dmarc_tags(rec)
    assert tags['p'] == 'Quarantine' and tags['pct'] == '50' and tags['sp'] == 'none'
    assert dns._dmarc_policy(rec) == 'quarantine'          # normalized lower-case
    # present but no explicit p tag → 'none'; absent → None
    assert dns._dmarc_policy(_records(DMARC=['v=DMARC1; rua=mailto:a@x'])) == 'none'
    assert dns._dmarc_policy(_records()) is None


def test_spf_all_qualifier_parsing():
    assert dns._spf_all_qualifier('v=spf1 include:x -all') == '-'
    assert dns._spf_all_qualifier('v=spf1 ~all') == '~'
    assert dns._spf_all_qualifier('v=spf1 ?all') == '?'
    assert dns._spf_all_qualifier('v=spf1 +all') == '+'
    assert dns._spf_all_qualifier('v=spf1 all') == '+'        # bare all → +
    assert dns._spf_all_qualifier('v=spf1 include:x') is None  # no all mechanism
    assert dns._spf_all_qualifier(None) is None


# ── fetch_records (injected query) ────────────────────────────────────────────

def test_fetch_records_probes_dmarc_and_dkim_selectors():
    def q(name, rtype):
        if name == '_dmarc.x.com' and rtype == 'TXT':
            return ['v=DMARC1; p=reject']
        if name == 'google._domainkey.x.com':
            return ['v=DKIM1; p=abc']
        if name == 'x.com' and rtype == 'A':
            return ['1.2.3.4']
        return []
    rec = dns.fetch_records('x.com', query=q)
    assert rec['A'] == ['1.2.3.4']
    assert rec['DMARC'] == ['v=DMARC1; p=reject']
    assert rec['DKIM'] == {'google': ['v=DKIM1; p=abc']}


# ── _doh_query parsing (network stubbed) ──────────────────────────────────────

def test_doh_query_parses_answer(monkeypatch):
    payload = {'Status': 0, 'Answer': [
        {'name': 'x.com.', 'type': 16, 'data': '"v=spf1 ~all"'},
        {'name': 'x.com.', 'type': 16, 'data': 'plain'}]}
    monkeypatch.setattr(dns, 'urlopen_text', lambda req, t, **k: json.dumps(payload))
    out = dns._doh_query('x.com', 'TXT')
    assert out == ['v=spf1 ~all', 'plain']        # quotes stripped


def test_doh_query_empty_on_error(monkeypatch):
    monkeypatch.setattr(dns, 'urlopen_text',
                        lambda *a, **k: (_ for _ in ()).throw(OSError('x')))
    assert dns._doh_query('x.com', 'A') == []


# ── discover (injected query) ─────────────────────────────────────────────────

def test_discover_success_and_domain_extraction():
    def q(name, rtype):
        return ['1.2.3.4'] if (name == 'x.com' and rtype == 'A') else []
    out = dns.discover('https://x.com:8443/path', query=q)
    assert out['status'] == 'Success' and out['domain'] == 'x.com'
    assert out['records']['A'] == ['1.2.3.4']


def test_discover_no_records():
    out = dns.discover('https://x.com', query=lambda n, t: [])
    assert out['status'] == 'No records' and out['findings'] == []


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline():
    out = dns.discover('https://x.com',
                       query=lambda n, t: ['1.2.3.4'] if t == 'A' else [])
    page = dns.render_html(out)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert '1.2.3.4' in page and 'SPF' in page


def test_render_html_no_records():
    assert 'не найдены' in dns.render_html({'status': 'No records'})


# ── integration: scan_diff dns section ────────────────────────────────────────

def _report_with_dns(email_auth):
    return {'phases': {'dns': {'status': 'Success',
                              'data': {'email_auth': email_auth}}}}


def test_scan_diff_reports_email_auth_change():
    a = _report_with_dns({'spf': None, 'dmarc': None,
                          'dkim_selectors': [], 'caa': False})
    b = _report_with_dns({'spf': 'v=spf1 ~all', 'dmarc': 'reject',
                          'dkim_selectors': ['google'], 'caa': True})
    d = scan_diff.diff(a, b)
    changed = {c['key']: (c['a'], c['b']) for c in d['sections']['dns']['changed']}
    assert changed['DMARC'] == ('—', 'reject')
    assert changed['SPF'][0] == '—' and changed['SPF'][1].startswith('v=spf1')
