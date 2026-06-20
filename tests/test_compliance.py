"""OWASP Top 10 / CWE compliance mapping (core/compliance.py, EPIC 16 wave 2 A3).

Pure, offline: classify maps a finding to OWASP/CWE; build_compliance rolls a
findings list up against the full Top 10 (clean categories included).
"""

from core import compliance


def _f(category, rule_id='', title='', severity='high', fid='x'):
    return {'id': fid, 'category': category, 'rule_id': rule_id,
            'title': title, 'severity': severity}


# ── classify ──────────────────────────────────────────────────────────────────

def test_classify_category_defaults():
    assert compliance.classify('header')['owasp'] == 'A05:2021'
    assert compliance.classify('secret')['owasp'] == 'A07:2021'
    assert compliance.classify('dependency')['owasp'] == 'A06:2021'
    assert 'CWE-798' in compliance.classify('secret')['cwe']


def test_classify_rule_map_overrides_category():
    # A generic vuln finding refined by its title keyword.
    c = compliance.classify('vuln', 'sqli', 'SQL injection in /search')
    assert c['owasp'] == 'A03:2021' and c['cwe'] == ['CWE-89']
    ssrf = compliance.classify('vuln', '', 'Server-Side Request Forgery')
    assert ssrf['owasp'] == 'A10:2021' and ssrf['cwe'] == ['CWE-918']


def test_classify_unrecognized_vuln_is_unmapped():
    c = compliance.classify('vuln', 'weird', 'Some odd thing')
    assert c['owasp'] is None and c['cwe'] == []


def test_classify_owasp_name_resolved():
    assert compliance.classify('header')['owasp_name'] == 'Security Misconfiguration'


# ── build_compliance ──────────────────────────────────────────────────────────

def test_build_lists_all_ten_categories():
    data = compliance.build_compliance([])
    assert len(data['by_owasp']) == 10
    assert [b['id'] for b in data['by_owasp']][0] == 'A01:2021'
    assert all(b['count'] == 0 for b in data['by_owasp'])
    assert data['summary']['categories_with_findings'] == 0


def test_build_groups_and_counts():
    findings = [
        _f('header', severity='medium', fid='h'),
        _f('secret', severity='critical', fid='s'),
        _f('cookie', severity='low', fid='c'),     # also A05
        _f('vuln', 'sqli', 'SQL injection', severity='high', fid='q'),
    ]
    data = compliance.build_compliance(findings)
    by_id = {b['id']: b for b in data['by_owasp']}
    assert by_id['A05:2021']['count'] == 2          # header + cookie
    assert by_id['A07:2021']['count'] == 1          # secret
    assert by_id['A03:2021']['count'] == 1          # sqli
    assert 'CWE-89' in by_id['A03:2021']['cwe']
    assert by_id['A05:2021']['severities'] == {'medium': 1, 'low': 1}
    s = data['summary']
    assert s['total_findings'] == 4 and s['categories_with_findings'] == 3
    assert s['worst_severity'] == 'critical' and s['unmapped'] == 0


def test_build_surfaces_unmapped():
    data = compliance.build_compliance([_f('vuln', 'x', 'Mystery', fid='m')])
    assert data['summary']['unmapped'] == 1
    assert data['unmapped'][0]['title'] == 'Mystery'
    assert all(b['count'] == 0 for b in data['by_owasp'])


def test_build_tolerates_non_dicts():
    data = compliance.build_compliance(['nope', None, _f('header')])
    assert data['summary']['total_findings'] == 1


def test_load_compliance_uses_active_findings():
    class _Store:
        def active_findings(self, project):
            return [_f('secret', fid='s')]
    data = compliance.load_compliance('p', store=_Store())
    assert data['summary']['total_findings'] == 1
    assert next(b for b in data['by_owasp'] if b['id'] == 'A07:2021')['count'] == 1
