"""Scan Diff — pure offline diff of two collection reports (no network)."""

from core.project import ProjectStore
from core.scan_diff import diff, diff_events, render_html, summarize_line


# ── synthetic report builders ────────────────────────────────────────────────

def _report(scan_id='A', pages=None, secrets=None, techs=None, cms=None,
            deps=None, headers=None, sec_headers=None, endpoints=None,
            findings=None, level='Low', risk_100=4, subdomains=None, cert=None,
            graphql=None, source_maps=None, cookies=None, historical=None):
    """A minimal but shape-faithful collection report."""
    phases = {
        'capture': {'status': 'Success',
                    'data': {'site_map': pages if pages is not None else []}},
        'api': {'status': 'Success',
                'data': {'details': secrets if secrets is not None else {}}},
        'recon': {'status': 'Success', 'data': {
            'technologies': techs if techs is not None else [],
            'cms': cms if cms is not None else [],
            'dependencies': {'libraries': deps if deps is not None else []},
            'server_headers': headers if headers is not None else {},
            'security_headers': sec_headers if sec_headers is not None else {},
        }},
        'vulns': {'status': 'Success',
                  'findings': findings if findings is not None else []},
    }
    if endpoints is not None:
        phases['katana'] = {'status': 'Success',
                            'data': {'endpoints': endpoints}}
    if subdomains is not None:
        phases['subdomains'] = {'status': 'Success',
                                'data': {'results': subdomains}}
    if cert is not None:
        phases['certificate'] = {'status': 'Success', 'data': cert}
    if cookies is not None:
        phases['cookies'] = {'status': 'Success', 'data': {'cookies': cookies}}
    if historical is not None:
        phases['historical'] = {'status': 'Success',
                                'data': {'interesting': historical}}
    if graphql is not None or source_maps is not None:
        data = {}
        if graphql is not None:
            data['graphql'] = graphql
        if source_maps is not None:
            data['source_maps'] = source_maps
        phases['security'] = {'status': 'Success', 'data': data}
    ts = f'2026-06-13T0{1 if scan_id == "A" else 2}:00:00'
    return {
        'scan_id': scan_id, 'finished_at': ts, 'started_at': ts,
        'phases': phases,
        'executive_summary': {'risk_level': level, 'risk_100': risk_100,
                              'metrics': {'risk_100': risk_100}},
    }


def _page(url, status=200, ctype='text/html'):
    return {'url': url, 'status': status, 'content_type': ctype, 'depth': 1}


# ── sections: added / removed / changed ──────────────────────────────────────

def test_pages_added_removed_changed():
    a = _report('A', pages=[_page('/x'), _page('/gone'), _page('/same')])
    b = _report('B', pages=[_page('/x', status=500), _page('/new'),
                            _page('/same')])
    sec = diff(a, b)['sections']['pages']
    assert sec['added'] == ['/new [200]']
    assert sec['removed'] == ['/gone [200]']
    assert sec['changed'] == [{'key': '/x', 'a': '200 (text/html)',
                               'b': '500 (text/html)'}]


def test_secrets_added_removed_and_masked():
    a = _report('A', secrets={'AWS': ['AKIAIOSFODNN7EXAMPLE']})
    b = _report('B', secrets={'Stripe': ['sk_live_abcdef123456']})
    sec = diff(a, b)['sections']['secrets']
    assert sec['added'] == ['Stripe: sk_liv…(20)']
    assert sec['removed'] == ['AWS: AKIAIO…(20)']
    # Full values never appear anywhere in the diff.
    assert 'AKIAIOSFODNN7EXAMPLE' not in str(diff(a, b))


def test_placeholder_secret_tagged_and_not_alertable():
    # A real (plausible) secret newly appears alongside a placeholder one.
    a = _report('A', secrets={})
    b = _report('B', secrets={'AWS Access Key': ['AKIAIOSFODNN7EXAMPLE'],
                              'Generic API Key': ['your_api_key_here']})
    d = diff(a, b)
    added = d['sections']['secrets']['added']
    # The placeholder is visibly tagged in the diff; the real one is not.
    assert any(x.endswith(' ⚠ placeholder') for x in added)
    assert any('AKIAIO' in x and '⚠ placeholder' not in x for x in added)
    # Only the plausible secret produces an alertable new_secret event.
    secret_events = [e for e in diff_events(d) if e['type'] == 'new_secret']
    assert len(secret_events) == 1
    assert 'AKIAIO' in secret_events[0]['title']


def test_new_historical_url_event():
    # A newly-surfaced interesting archived URL produces a timeline event.
    a = _report('A', historical=['https://x.com/api/v1'])
    b = _report('B', historical=['https://x.com/api/v1',
                                 'https://x.com/admin/login'])
    sec = diff(a, b)['sections']['historical']
    assert sec['added'] == ['https://x.com/admin/login']
    events = [e for e in diff_events(diff(a, b))
              if e['type'] == 'new_historical_url']
    assert len(events) == 1
    assert 'admin/login' in events[0]['title']


def test_osint_discovery_events_end_to_end():
    # A newly-seen email / employee / CT certificate each produces a timeline event.
    a, b = _report('A'), _report('B')
    for r, extra in ((a, False), (b, True)):
        r['phases']['emails'] = {'status': 'Success', 'data': {
            'on_domain': ['ceo@x.com'] + (['new@x.com'] if extra else []),
            'external': []}}
        r['phases']['employees'] = {'status': 'Success', 'data': {'people':
            [{'name': 'Jane Doe', 'title': 'CTO'}]
            + ([{'name': 'New Hire', 'title': 'Eng'}] if extra else [])}}
        r['phases']['ct'] = {'status': 'Success', 'data': {'certs':
            [{'id': 1, 'not_before': '2026-01-01', 'issuer': 'LE', 'names': ['x.com']}]
            + ([{'id': 2, 'not_before': '2026-06-01', 'issuer': 'LE',
                 'names': ['new.x.com']}] if extra else [])}}
    types = [e['type'] for e in diff_events(diff(a, b))]
    assert 'new_email' in types
    assert 'new_employee' in types
    assert 'new_ct_cert' in types


def test_dns_email_auth_weakened_end_to_end():
    # SPF removed and DMARC downgraded between scans → two regression events.
    a, b = _report('A'), _report('B')
    a['phases']['dns'] = {'status': 'Success', 'data': {'email_auth': {
        'spf': 'v=spf1 -all', 'dmarc': 'reject', 'dkim_selectors': [], 'caa': True}}}
    b['phases']['dns'] = {'status': 'Success', 'data': {'email_auth': {
        'spf': None, 'dmarc': 'none', 'dkim_selectors': [], 'caa': True}}}
    types = [e['type'] for e in diff_events(diff(a, b))]
    assert types.count('dns_email_auth_weakened') == 2


def test_exposure_cluster_event_end_to_end():
    # A shared-infra cluster forming between scans → a new_exposure_cluster event.
    a = _report('A', subdomains=[{'subdomain': 'a.x.com'}])
    b = _report('B', subdomains=[{'subdomain': 'a.x.com'}])
    a['asset_graph'] = {'shared_infra': []}
    b['asset_graph'] = {'shared_infra': [{'type': 'ip', 'node': '1.2.3.4',
                                          'count': 3}]}
    sec = diff(a, b)['sections']['exposure']
    assert sec['added'] == ['ip 1.2.3.4 — 3 активов']
    types = [e['type'] for e in diff_events(diff(a, b))]
    assert 'new_exposure_cluster' in types


def test_technology_version_change_and_cms_union():
    a = _report('A', techs=[{'name': 'nginx', 'category': 'Server',
                             'version': '1.18'}], cms=['WordPress'])
    b = _report('B', techs=[{'name': 'nginx', 'category': 'Server',
                             'version': '1.25'},
                            {'name': 'Cloudflare', 'category': 'CDN'}])
    sec = diff(a, b)['sections']['technologies']
    assert sec['added'] == ['Cloudflare']
    assert sec['removed'] == ['WordPress']          # cms folds into the section
    assert sec['changed'] == [{'key': 'nginx', 'a': '1.18', 'b': '1.25'}]


def test_dependency_vulnerable_flag_change():
    a = _report('A', deps=[{'name': 'jquery', 'version': '3.6.0'}])
    b = _report('B', deps=[{'name': 'jquery', 'version': '1.8.0',
                            'vulnerabilities': [{'severity': 'High'}]}])
    sec = diff(a, b)['sections']['dependencies']
    assert sec['changed'] == [{'key': 'jquery', 'a': '3.6.0', 'b': '1.8.0 ⚠'}]


def test_added_vulnerable_dependency_emits_event():
    # End-to-end: a newly-present vulnerable library yields the ' ⚠ vulnerable'
    # label the diff_events classifier keys on → a high, alertable event.
    a = _report('A', deps=[])
    b = _report('B', deps=[{'name': 'jquery', 'version': '1.8.0',
                            'vulnerabilities': [{'severity': 'High'}]}])
    d = diff(a, b)
    assert d['sections']['dependencies']['added'] == ['jquery 1.8.0 ⚠ vulnerable']
    types = {e['type'] for e in diff_events(d)}
    assert 'new_vulnerable_dependency' in types


def test_removed_security_header_emits_event():
    # End-to-end: a security header present in A and gone in B lands in the
    # headers section's 'removed' list and classifies as a high, alertable
    # regression. recon stores security-header names lowercased.
    a = _report('A', sec_headers={'strict-transport-security': 'max-age=31536000'})
    b = _report('B', sec_headers={})
    d = diff(a, b)
    assert 'strict-transport-security: max-age=31536000' \
        in d['sections']['headers']['removed']
    types = {e['type'] for e in diff_events(d)}
    assert 'security_header_removed' in types


def test_headers_merge_server_and_security():
    a = _report('A', headers={'Server': 'nginx'},
                sec_headers={'X-Frame-Options': 'DENY'})
    b = _report('B', headers={'Server': 'cloudflare'},
                sec_headers={'Content-Security-Policy': "default-src 'self'"})
    sec = diff(a, b)['sections']['headers']
    assert sec['added'] == ["Content-Security-Policy: default-src 'self'"]
    assert sec['removed'] == ['X-Frame-Options: DENY']
    assert sec['changed'] == [{'key': 'Server', 'a': 'nginx',
                               'b': 'cloudflare'}]


def test_findings_added():
    a = _report('A')
    b = _report('B', findings=[{'severity': 'High', 'title': 'CSP missing'}])
    sec = diff(a, b)['sections']['findings']
    assert sec['added'] == ['[High] CSP missing']
    assert sec['removed'] == []


def test_subdomains_added_removed_with_takeover_flag():
    a = _report('A', subdomains=[{'subdomain': 'old.x.com'},
                                 {'subdomain': 'keep.x.com'}])
    b = _report('B', subdomains=[{'subdomain': 'keep.x.com'},
                                 {'subdomain': 'new.x.com', 'takeover': True}])
    sec = diff(a, b)['sections']['subdomains']
    assert sec['added'] == ['new.x.com ⚠ takeover']   # takeover flagged
    assert sec['removed'] == ['old.x.com']


def test_certificate_renewal_shows_changed_fields():
    a = _report('A', cert={'issuer': 'R3 (Lets Encrypt)', 'serial': 'AA',
                           'not_after': 'Aug 1 2026', 'fingerprint_sha256': 'a' * 64})
    b = _report('B', cert={'issuer': 'R3 (Lets Encrypt)', 'serial': 'BB',
                           'not_after': 'Nov 1 2026', 'fingerprint_sha256': 'b' * 64})
    sec = diff(a, b)['sections']['certificates']
    changed = {c['key']: (c['a'], c['b']) for c in sec['changed']}
    assert changed['serial'] == ('AA', 'BB')               # renewed
    assert changed['not_after'] == ('Aug 1 2026', 'Nov 1 2026')
    assert 'fingerprint_sha256' in changed
    assert sec['added'] == [] and sec['removed'] == []     # same field set


def test_certificate_added_field():
    a = _report('A', cert={'subject': 'x.com'})
    b = _report('B', cert={'subject': 'x.com',
                           'sans': 'x.com, www.x.com'})       # SAN appeared
    sec = diff(a, b)['sections']['certificates']
    assert sec['added'] == ['sans: x.com, www.x.com']


def test_certificate_expiry_status_classified_against_scan_time():
    # B's cert is already past its deadline relative to B's scan time → the
    # synthetic expiry status surfaces it (judged against started_at, not today).
    a = _report('A', cert={'subject': 'x.com'})                  # no not_after
    b = _report('B', cert={'subject': 'x.com', 'not_after': '2026-06-01'})
    sec = diff(a, b)['sections']['certificates']
    assert 'expiry: expired' in sec['added']


def test_certificate_expires_between_scans_is_changed():
    a = _report('A', cert={'subject': 'x.com', 'not_after': '2027-01-01'})  # valid
    b = _report('B', cert={'subject': 'x.com', 'not_after': '2026-06-01'})  # expired
    changed = {c['key']: (c['a'], c['b'])
               for c in diff(a, b)['sections']['certificates']['changed']}
    assert changed['expiry'] == ('valid', 'expired')


def test_certificate_renewal_flips_expiry_status_back():
    a = _report('A', cert={'subject': 'x.com', 'not_after': '2026-06-20'})  # expiring
    b = _report('B', cert={'subject': 'x.com', 'not_after': '2027-06-20'})  # valid
    changed = {c['key']: (c['a'], c['b'])
               for c in diff(a, b)['sections']['certificates']['changed']}
    assert changed['expiry'] == ('expiring', 'valid')


def test_graphql_endpoint_added_and_introspection_opens():
    a = _report('A', graphql=[{'url': 'https://x.com/graphql', 'graphql': True,
                               'introspection': False}])
    b = _report('B', graphql=[
        {'url': 'https://x.com/graphql', 'graphql': True, 'introspection': True},
        {'url': 'https://x.com/v2/graphql', 'graphql': True, 'introspection': False},
    ])
    sec = diff(a, b)['sections']['graphql']
    # the new endpoint is an addition; the existing one flipped open → changed
    assert sec['added'] == ['https://x.com/v2/graphql: reachable']
    changed = {c['key']: (c['a'], c['b']) for c in sec['changed']}
    assert changed['https://x.com/graphql'] == ('reachable', 'introspection on')


def test_graphql_skipped_when_security_phase_absent_in_one():
    a = _report('A', graphql=[{'url': 'https://x.com/graphql',
                               'introspection': False}])
    b = _report('B')                            # no security phase in B
    d = diff(a, b)
    assert 'graphql' in d['skipped'] and 'graphql' not in d['sections']


def test_sourcemap_leak_added_between_scans():
    # Only a map that leaks the original source (has_content) is surfaced; a map
    # without content is not a leak and must not appear. A newly-leaking map
    # shows as an added row between scans.
    a = _report('A', source_maps=[
        {'url': 'https://x.com/vendor.js.map', 'has_content': False}])
    b = _report('B', source_maps=[
        {'url': 'https://x.com/vendor.js.map', 'has_content': False},
        {'url': 'https://x.com/app.js.map', 'has_content': True}])
    sec = diff(a, b)['sections']['sourcemap']
    assert sec['added'] == ['https://x.com/app.js.map']
    assert sec['removed'] == []


def test_sourcemap_skipped_when_security_phase_absent_in_one():
    a = _report('A', source_maps=[{'url': 'https://x.com/app.js.map',
                                   'has_content': True}])
    b = _report('B')                            # no security phase in B
    d = diff(a, b)
    assert 'sourcemap' in d['skipped'] and 'sourcemap' not in d['sections']


def _cookie(name, verdict):
    return {'name': name, 'verdict': verdict}


def test_cookie_degrade_is_a_changed_row_not_rediscovery():
    # A cookie present in both scans that loses protection (Strong → Weak) must
    # surface as a *changed* row keyed by name, not an add/remove churn.
    a = _report('A', cookies=[_cookie('sid', 'Strong')])
    b = _report('B', cookies=[_cookie('sid', 'Weak')])
    sec = diff(a, b)['sections']['cookies']
    assert sec['added'] == [] and sec['removed'] == []
    assert sec['changed'] == [{'key': 'sid', 'a': 'Strong', 'b': 'Weak'}]


def test_cookie_newly_served_weak_is_added():
    a = _report('A', cookies=[_cookie('sid', 'Strong')])
    b = _report('B', cookies=[_cookie('sid', 'Strong'), _cookie('tracker', 'Weak')])
    sec = diff(a, b)['sections']['cookies']
    assert sec['added'] == ['tracker: Weak']


def test_cookies_skipped_when_phase_absent_in_one():
    a = _report('A', cookies=[_cookie('sid', 'Weak')])
    b = _report('B')                            # no cookies phase in B
    d = diff(a, b)
    assert 'cookies' in d['skipped'] and 'cookies' not in d['sections']


def test_certificate_skipped_when_phase_absent_in_one():
    a = _report('A', cert={'subject': 'x.com'})
    b = _report('B')                            # no certificate phase in B
    d = diff(a, b)
    assert 'certificates' not in d['sections']
    assert 'certificates' in d['skipped']


def test_subdomains_skipped_when_phase_absent_in_one():
    a = _report('A', subdomains=[{'subdomain': 'a.x.com'}])
    b = _report('B')                       # no subdomain phase in B
    d = diff(a, b)
    assert 'subdomains' not in d['sections']
    assert 'subdomains' in d['skipped']


def test_endpoints_compared_when_katana_ran_in_both():
    a = _report('A', endpoints=['https://x/api/v1'])
    b = _report('B', endpoints=['https://x/api/v1', 'https://x/api/v2'])
    sec = diff(a, b)['sections']['endpoints']
    assert sec['added'] == ['https://x/api/v2']


# ── honesty: failed / absent / legacy phases are skipped, not noise ──────────

def test_phase_absent_in_one_scan_is_skipped_not_removed():
    a = _report('A', endpoints=['https://x/api/v1'])
    b = _report('B')                       # katana didn't run in B
    d = diff(a, b)
    assert 'endpoints' not in d['sections']
    assert 'B' in d['skipped']['endpoints']


def test_phase_error_is_skipped():
    a = _report('A')
    b = _report('B')
    b['phases']['api'] = {'status': 'Error', 'error': 'boom'}
    d = diff(a, b)
    assert 'secrets' not in d['sections']
    assert 'api' in d['skipped']['secrets']


def test_legacy_scan_without_site_map_is_skipped():
    a = _report('A')
    del a['phases']['capture']['data']['site_map']   # pre-H1 scan shape
    d = diff(a, _report('B'))
    assert 'pages' not in d['sections']
    assert 'легаси' in d['skipped']['pages']


# ── identical scans / headline ───────────────────────────────────────────────

def test_identical_reports_are_empty():
    a = _report('A', pages=[_page('/x')], headers={'Server': 'nginx'})
    b = _report('B', pages=[_page('/x')], headers={'Server': 'nginx'})
    d = diff(a, b)
    assert d['is_empty'] is True
    assert 'Изменений не обнаружено' in summarize_line(d)


def test_risk_headline_and_summary_line():
    a = _report('A', level='Low', risk_100=4)
    b = _report('B', level='Critical', risk_100=100,
                findings=[{'severity': 'High', 'title': 'x'}])
    d = diff(a, b)
    assert d['risk'] == {'level_a': 'Low', 'level_b': 'Critical',
                         'risk_100_a': 4, 'risk_100_b': 100}
    line = summarize_line(d)
    assert 'Findings: +1' in line and 'Low 4/100 → Critical 100/100' in line


def test_tolerates_empty_reports():
    d = diff({}, {})
    assert d['sections'] == {}
    assert set(d['skipped']) == {'pages', 'subdomains', 'secrets',
                                 'technologies', 'dependencies', 'headers',
                                 'certificates', 'endpoints', 'apis',
                                 'historical', 'dns', 'emails', 'employees',
                                 'ct', 'graphql', 'sourcemap', 'cookies',
                                 'findings', 'exposure'}
    assert d['is_empty'] is True


# ── HTML render: offline + escaping ──────────────────────────────────────────

def test_render_is_offline_and_self_contained():
    a = _report('A', pages=[_page('/x')])
    b = _report('B', pages=[_page('/y')])
    page = render_html(diff(a, b))
    assert page.startswith('<!DOCTYPE html>')
    for forbidden in ('<script', 'http://', 'https://cdn', '<link'):
        assert forbidden not in page


def test_render_escapes_hostile_values():
    a = _report('A', headers={'Server': '<img src=x onerror=alert(1)>'})
    b = _report('B', headers={})
    page = render_html(diff(a, b))
    assert '<img src=x' not in page
    assert '&lt;img' in page


def test_render_shows_skipped_and_empty_state():
    d = diff(_report('A'), _report('B'))
    page = render_html(d)
    assert 'пропущено' in page                  # katana skipped in both
    assert 'Изменений между сканами не обнаружено' in page


# ── integration with the project workspace ──────────────────────────────────

def test_project_load_scan_report_roundtrip(tmp_path):
    import json
    p = ProjectStore(tmp_path).get_or_create('https://example.com')
    for scan_id, level in (('20260613_010000', 'Low'),
                           ('20260613_020000', 'High')):
        scan_dir = p.start_scan(scan_id)
        report = _report(scan_id, level=level)
        (scan_dir / 'report.json').write_text(
            json.dumps(report, ensure_ascii=False), encoding='utf-8')
    a = p.load_scan_report('20260613_010000')
    b = p.load_scan_report('20260613_020000')
    d = diff(a, b)
    assert d['risk']['level_a'] == 'Low' and d['risk']['level_b'] == 'High'
    assert p.load_scan_report('nope') is None
