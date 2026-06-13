"""Scan Diff — pure offline diff of two collection reports (no network)."""

from core.project import ProjectStore
from core.scan_diff import diff, render_html, summarize_line


# ── synthetic report builders ────────────────────────────────────────────────

def _report(scan_id='A', pages=None, secrets=None, techs=None, cms=None,
            deps=None, headers=None, sec_headers=None, endpoints=None,
            findings=None, level='Low', risk_100=4):
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
    return {
        'scan_id': scan_id, 'finished_at': f'2026-06-13T0{1 if scan_id == "A" else 2}:00:00',
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
    assert set(d['skipped']) == {'pages', 'secrets', 'technologies',
                                 'dependencies', 'headers', 'endpoints',
                                 'findings'}
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
