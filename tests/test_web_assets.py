"""Web console Asset Inventory endpoint (remote/web_app.py, web parity).

Pure helper over the asset store + the live HTTP endpoint via TestClient. The
assets DB is the per-test temp file from conftest's autouse ``_isolate_assets_db``
fixture, so seeding via ``AssetStore()`` and the web_app helper hit the same store.
Assets are read-only on the web (no triage), so there is no POST endpoint.
"""

import pytest

import remote.web_app as wa
from core.asset_adapter import Asset
from core.asset_store import AssetStore


def _seed():
    s = AssetStore()
    s.sync('p1', 's1', [Asset('subdomain', 'api.x.com'),
                        Asset('ip', '1.2.3.4')])
    s.sync('p2', 's1', [Asset('domain', 'y.com')])
    return s


# ── pure helper ──────────────────────────────────────────────────────────────

def test_assets_list_returns_projects_assets_summary():
    _seed()
    d = wa._assets_list()
    assert {p['project'] for p in d['projects']} == {'p1', 'p2'}
    assert len(d['assets']) == 3
    assert d['summary']['total'] == 3 and d['summary']['active'] == 3  # all projects


def test_assets_list_filters():
    _seed()
    d = wa._assets_list(project='p1', type='subdomain')
    assert {a['value'] for a in d['assets']} == {'api.x.com'}
    # summary is scoped to the project
    assert d['summary']['total'] == 2


# ── dashboard surface ────────────────────────────────────────────────────────

def test_dashboard_exposes_assets():
    html = wa._DASHBOARD
    assert 'showAssets()' in html and '/assets' in html


# ── live endpoint ────────────────────────────────────────────────────────────

def test_assets_endpoint_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed()
    client = TestClient(wa.app)

    r = client.get('/assets')
    assert r.status_code == 200
    assert len(r.json()['assets']) == 3

    r = client.get('/assets', params={'project': 'p1', 'type': 'subdomain'})
    assert [a['value'] for a in r.json()['assets']] == ['api.x.com']


def test_assets_list_query_filter():
    _seed()
    d = wa._assets_list(project='p1', query='api')
    assert {a['value'] for a in d['assets']} == {'api.x.com'}
    assert wa._assets_list(query='nomatch')['assets'] == []
