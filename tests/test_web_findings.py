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
