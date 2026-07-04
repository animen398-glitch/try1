"""Web console Findings endpoints (remote/web_app.py, F1 T1.6).

Pure helpers over the findings store + the live HTTP endpoints via TestClient.
The findings DB is the per-test temp file from conftest's autouse
``_isolate_findings_db`` fixture, so seeding via ``FindingsStore()`` and the
web_app helpers hit the same store.
"""

import pytest

import remote.web_app as wa
from core.finding_fingerprint import scoped_id
from core.findings_store import FindingsStore


def _seed():
    s = FindingsStore()
    s.upsert('p1', {'id': 'f-a', 'category': 'header', 'rule_id': 'csp',
                    'title': 'Weak CSP', 'severity': 'high'})
    s.upsert('p1', {'id': 'f-b', 'category': 'cookie', 'rule_id': 'sess',
                    'title': 'Insecure cookie', 'severity': 'low'})
    s.upsert('p2', {'id': 'f-c', 'category': 'secret', 'rule_id': 'aws',
                    'title': 'AWS key', 'severity': 'critical'})
    return s


# ── pure helpers ───────────────────────────────────────────────────────────────

def test_findings_list_returns_projects_findings_summary():
    _seed()
    d = wa._findings_list()
    assert {p['project'] for p in d['projects']} == {'p1', 'p2'}
    assert len(d['findings']) == 3
    assert d['summary']['total'] == 3 and d['summary']['active'] == 3


def test_findings_list_filters():
    _seed()
    d = wa._findings_list(project='p1', severity='high')
    assert {f['title'] for f in d['findings']} == {'Weak CSP'}
    # summary is scoped to the project
    assert d['summary']['total'] == 2


def test_findings_list_enriches_with_knowledge():
    # F-O4: each finding carries description/impact/remediation.
    _seed()
    f = wa._findings_list(project='p2')['findings'][0]   # the secret finding
    assert f['description'] and f['impact'] and f['remediation']
    assert 'ротируйте' in f['remediation']               # secret remediation


def test_findings_list_threat_block_tightens_sla():
    # A KEV finding carries the threat block and its SLA is tightened (the threat
    # annotate runs before the SLA annotate — consistent with the GUI/report).
    from core.cve_store import CVEStore
    cve = 'CVE-2021-44228'
    CVEStore().put_cve_threat(cve, {'kev': True})        # isolated per-test (conftest)
    s = FindingsStore()
    s.upsert('pk', {'id': 'f-kev', 'category': 'vuln', 'rule_id': cve,
                    'title': 'Log4Shell', 'severity': 'high', 'evidence': None})
    f = next(x for x in wa._findings_list(project='pk')['findings']
             if x['id'] == scoped_id('pk', 'f-kev'))
    assert f['threat']['kev'] is True
    assert f['sla']['tightened_by'] == 'kev'
    assert f['sla']['sla_days'] == 8                     # 30 → round(30 × 0.25)


def test_findings_set_status_ok():
    s = _seed()
    fid = scoped_id('p1', 'f-a')        # the id GET /findings would return
    out = wa._findings_set_status(fid, 'IGNORED', note='accepted risk')
    assert out['status'] == 'ok'
    assert out['finding']['status'] == 'IGNORED'
    assert s.get(fid)['status'] == 'IGNORED'
    assert s.events(fid)[-1]['note'] == 'accepted risk'


def test_findings_set_status_unknown_status():
    _seed()
    out = wa._findings_set_status('f-a', 'BOGUS')
    assert 'unknown status' in out['error']


def test_findings_set_status_unknown_finding():
    _seed()
    out = wa._findings_set_status('deadbeef', 'FIXED')
    assert 'not found' in out['error']


# ── dashboard surface ──────────────────────────────────────────────────────────

def test_dashboard_exposes_findings():
    html = wa._DASHBOARD
    assert 'showFindings()' in html and '/findings' in html


def test_findings_sarif_helper_emits_active_findings():
    import json
    _seed()
    doc = json.loads(wa._findings_sarif('p2'))
    assert doc['version'] == '2.1.0'
    results = doc['runs'][0]['results']
    assert [r['ruleId'] for r in results] == ['aws']   # the critical secret
    assert results[0]['level'] == 'error'
    # tool version is wired from config.APP_VERSION (non-empty).
    assert doc['runs'][0]['tool']['driver']['version']


def test_findings_sarif_helper_always_valid_when_empty():
    import json
    doc = json.loads(wa._findings_sarif('nope'))
    assert doc['version'] == '2.1.0' and doc['runs'][0]['results'] == []


# ── live endpoints ─────────────────────────────────────────────────────────────

def test_finding_assign_and_triage_helpers():
    _seed()
    fid = scoped_id('p1', 'f-a')
    assert wa._finding_assign(fid, 'alice')['assignee'] == 'alice'
    assert wa._finding_assign(fid, '')['assignee'] == ''        # unassign
    t = wa._finding_triage(fid)
    assert t['assignee'] == '' and t['comments'] == []
    assert 'not found' in wa._finding_assign('zzz', 'x').get('error', '')
    assert 'not found' in wa._finding_triage('zzz').get('error', '')


def test_finding_comment_helper():
    _seed()
    fid = scoped_id('p1', 'f-a')
    out = wa._finding_comment(fid, 'looks exploitable', author='alice')
    assert out['comment']['text'] == 'looks exploitable'
    assert wa._finding_triage(fid)['comments'][0]['author'] == 'alice'
    assert 'required' in wa._finding_comment(fid, '   ').get('error', '')  # empty
    assert 'not found' in wa._finding_comment('zzz', 'x').get('error', '')


def test_findings_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed()
    client = TestClient(wa.app)

    r = client.get('/findings')
    assert r.status_code == 200
    assert r.json()['summary']['total'] == 3

    r = client.get('/findings', params={'project': 'p1', 'severity': 'high'})
    assert [f['title'] for f in r.json()['findings']] == ['Weak CSP']

    # Change a status (using the scoped id a client gets from GET /findings).
    fid = scoped_id('p1', 'f-a')
    r = client.post(f'/findings/{fid}/status',
                    json={'status': 'FALSE_POSITIVE', 'note': 'n/a'})
    assert r.status_code == 200 and r.json()['finding']['status'] == 'FALSE_POSITIVE'

    # Unknown status -> 400; unknown finding -> 404.
    assert client.post('/findings/f-a/status',
                       json={'status': 'NOPE'}).status_code == 400
    assert client.post('/findings/zzz/status',
                       json={'status': 'FIXED'}).status_code == 404

    # triage: assign + comment + read-back
    r = client.post(f'/findings/{fid}/assign', json={'assignee': 'alice'})
    assert r.status_code == 200 and r.json()['assignee'] == 'alice'
    r = client.post(f'/findings/{fid}/comment',
                    json={'text': 'investigate', 'author': 'bob'})
    assert r.status_code == 200 and r.json()['comment']['text'] == 'investigate'
    body = client.get(f'/findings/{fid}/triage').json()
    assert body['assignee'] == 'alice' and body['comments'][0]['author'] == 'bob'
    # empty comment -> 400; unknown finding -> 404
    assert client.post(f'/findings/{fid}/comment',
                       json={'text': ''}).status_code == 400
    assert client.post('/findings/zzz/assign',
                       json={'assignee': 'x'}).status_code == 404
    assert client.get('/findings/zzz/triage').status_code == 404


def test_findings_sarif_endpoint_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    import json
    from fastapi.testclient import TestClient
    _seed()
    client = TestClient(wa.app)
    r = client.get('/findings.sarif', params={'project': 'p1'})
    assert r.status_code == 200
    assert r.headers['content-type'].startswith('application/sarif+json')
    doc = json.loads(r.text)
    assert doc['version'] == '2.1.0'
    assert {res['ruleId'] for res in doc['runs'][0]['results']} == {'csp', 'sess'}


# ── bulk triage (multi-finding status / assign) ─────────────────────────────────

def test_findings_bulk_status_helper():
    s = _seed()
    ids = [scoped_id('p1', 'f-a'), scoped_id('p1', 'f-b')]
    out = wa._findings_bulk_status(ids + ['ghost'], 'FIXED')
    assert out['status'] == 'ok'
    assert set(out['updated']) == set(ids)
    assert out['missing'] == ['ghost']
    assert all(s.get(i)['status'] == 'FIXED' for i in ids)


def test_findings_bulk_status_unknown_status():
    _seed()
    out = wa._findings_bulk_status([scoped_id('p1', 'f-a')], 'BOGUS')
    assert 'unknown status' in out['error']


def test_findings_bulk_assign_helper():
    s = _seed()
    ids = [scoped_id('p1', 'f-a'), scoped_id('p2', 'f-c')]
    out = wa._findings_bulk_assign(ids, 'alice')
    assert out['assignee'] == 'alice'
    assert set(out['updated']) == set(ids)
    assert all(s.get_assignee(i) == 'alice' for i in ids)


def test_findings_bulk_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed()
    client = TestClient(wa.app)
    ids = [scoped_id('p1', 'f-a'), scoped_id('p1', 'f-b')]

    # the literal 'bulk' path is not captured as a {finding_id}
    r = client.post('/findings/bulk/status', json={'ids': ids, 'status': 'FIXED'})
    assert r.status_code == 200
    assert set(r.json()['updated']) == set(ids)

    ra = client.post('/findings/bulk/assign', json={'ids': ids, 'assignee': 'bob'})
    assert ra.status_code == 200 and ra.json()['assignee'] == 'bob'

    # a bad status is a 400, not a 404-through-{finding_id}
    r400 = client.post('/findings/bulk/status', json={'ids': ids, 'status': 'NOPE'})
    assert r400.status_code == 400
