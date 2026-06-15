"""Web console correlation endpoint (remote/web_app.py, F-K4 web parity).

A pure helper over core.correlation plus the live HTTP endpoint via TestClient.
The findings/assets stores are the conftest-isolated per-test DBs.
"""

import pytest

import remote.web_app as wa


def _seed(project='p'):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    FindingsStore().sync(project, 's1', [{
        'category': 'graphql', 'title': 'GraphQL introspection',
        'severity': 'high', 'location': 'https://api.acme.com/graphql'}])
    AssetStore().sync(project, 's1', [
        Asset('subdomain', 'api.acme.com', attrs={'ip': '1.2.3.4'}),
        Asset('endpoint', 'api.acme.com/graphql')])


# ── pure helper ──────────────────────────────────────────────────────────────────

def test_correlation_view_for_project():
    _seed('p')
    d = wa._correlation_view('p')
    assert 'error' not in d
    assert d['summary']['correlated'] == 1
    api = next(r for r in d['exposure'] if r['value'] == 'api.acme.com')
    assert api['worst'] == 'high'


def test_correlation_view_no_project_is_empty():
    d = wa._correlation_view(None)
    assert d['exposure'] == [] and d['summary'] == {}


# ── console surface ──────────────────────────────────────────────────────────────

def test_dashboard_exposes_correlation():
    html = wa._DASHBOARD
    assert 'showCorrelation()' in html and '/correlation' in html


# ── live endpoint ────────────────────────────────────────────────────────────────

def test_correlation_endpoint_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed('p')
    client = TestClient(wa.app)

    r = client.get('/correlation', params={'project': 'p'})
    assert r.status_code == 200
    body = r.json()
    assert body['summary']['correlated'] == 1
    assert any(a['value'] == 'api.acme.com' for a in body['exposure'])
