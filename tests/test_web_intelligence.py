"""Core Intelligence — web endpoint + integration (remote/web_app.py, EPIC 7).

Integration: seeds the real findings + asset stores (conftest-isolated tmp DBs),
then drives load_intelligence end-to-end (findings → correlation → asset graph →
priority/confidence ranking) through the web helper and the live endpoint.
"""

import pytest

import remote.web_app as wa


def _seed(project='p'):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    FindingsStore().sync(project, 's1', [
        # high-severity CVE on a co-hosted asset → should top the ranking
        {'category': 'vuln', 'rule_id': 'cve-2021-1', 'severity': 'high',
         'title': 'CVE-2021-1 in lib', 'location': 'a.acme.com/app.js',
         'evidence': {'sources': ['nuclei', 'osv']}},
        # a medium generic finding elsewhere
        {'category': 'vuln', 'severity': 'medium', 'title': 'Verbose error',
         'location': 'b.acme.com/x'},
    ])
    AssetStore().sync(project, 's1', [
        Asset('subdomain', 'a.acme.com', attrs={'ip': '1.2.3.4'}),
        Asset('subdomain', 'b.acme.com', attrs={'ip': '1.2.3.4'}),
        Asset('ip', '1.2.3.4', attrs={'asn': 'AS1'}),
        Asset('endpoint', 'a.acme.com/app.js')])


# ── integration via the stores ────────────────────────────────────────────────

def test_intelligence_view_ranks_and_scores():
    _seed('p')
    d = wa._intelligence_view('p')
    assert 'error' not in d
    assert d['summary']['findings'] == 2
    top = d['items'][0]
    assert 'CVE-2021-1' in top['title']            # high+CVE+corroborated+co-hosted
    assert top['confidence'] >= 85                 # CVE base + corroboration
    assert top['priority'] >= d['items'][1]['priority']
    assert 'impact' in top['explanation']          # explanation reused from catalog


def test_intelligence_view_no_project_is_empty():
    d = wa._intelligence_view(None)
    assert d['items'] == [] and d['summary'] == {}


def test_dashboard_exposes_intelligence():
    html = wa._DASHBOARD
    assert 'showIntelligence()' in html and '/intelligence' in html


# ── live endpoint ────────────────────────────────────────────────────────────────

def test_intelligence_endpoint_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed('p')
    client = TestClient(wa.app)
    r = client.get('/intelligence', params={'project': 'p'})
    assert r.status_code == 200
    body = r.json()
    assert body['summary']['findings'] == 2
    assert any('CVE-2021-1' in i['title'] for i in body['items'])


# ── Asset Criticality + Attack Paths web parity (EPIC 9/11) ───────────────────

def test_criticality_view_ranks_assets():
    _seed('p')
    d = wa._criticality_view('p')
    assert 'error' not in d and d['summary']['assets'] >= 1
    # the shared IP (two subdomains resolve to it) tops the ranking
    assert d['items'][0]['type'] == 'ip'


def test_attack_paths_view_derives_lateral_route():
    _seed('p')
    d = wa._attack_paths_view('p')
    assert 'error' not in d
    # a.acme.com (has findings) shares 1.2.3.4 with b.acme.com → one path
    assert d['summary']['paths'] >= 1


def test_criticality_and_paths_no_project_is_empty():
    assert wa._criticality_view(None)['items'] == []
    assert wa._attack_paths_view(None)['paths'] == []


def test_dashboard_exposes_criticality_and_paths():
    html = wa._DASHBOARD
    assert 'showCriticality()' in html and '/criticality' in html
    assert 'showAttackPaths()' in html and '/attack-paths' in html


def test_criticality_paths_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed('p')
    client = TestClient(wa.app)
    assert client.get('/criticality', params={'project': 'p'}).status_code == 200
    assert client.get('/attack-paths', params={'project': 'p'}).status_code == 200
