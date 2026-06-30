"""Web console auth & safe bind (remote/web_app.py).

Loopback-by-default bind + an app-wide token gate. The console is never
reachable from the LAN unauthenticated; loopback with no token stays open
(single-user desktop). Pure helper + live TestClient.
"""

import pytest

import remote.web_app as wa


# ── resolve_web_console (host + token resolution) ──────────────────────────────

def test_resolve_loopback_default_no_token(monkeypatch):
    monkeypatch.setattr(wa, 'load_settings', lambda: {'web_console': {}})
    monkeypatch.delenv('ASA_WEB_TOKEN', raising=False)
    host, token = wa.resolve_web_console()
    assert host == '127.0.0.1' and token == ''        # safe default, open loopback


def test_resolve_allow_lan_auto_generates_token(monkeypatch):
    monkeypatch.setattr(wa, 'load_settings',
                        lambda: {'web_console': {'allow_lan': True, 'token': ''}})
    monkeypatch.delenv('ASA_WEB_TOKEN', raising=False)
    host, token = wa.resolve_web_console()
    assert host == '0.0.0.0' and token                # never LAN-open without a token


def test_resolve_explicit_lan_host_auto_generates_token(monkeypatch):
    monkeypatch.setattr(wa, 'load_settings', lambda: {'web_console': {}})
    monkeypatch.delenv('ASA_WEB_TOKEN', raising=False)
    host, token = wa.resolve_web_console('0.0.0.0')
    assert host == '0.0.0.0' and token


def test_resolve_env_token_overrides_settings(monkeypatch):
    monkeypatch.setattr(wa, 'load_settings',
                        lambda: {'web_console': {'token': 'fromsettings'}})
    monkeypatch.setenv('ASA_WEB_TOKEN', 'fromenv')
    _, token = wa.resolve_web_console()
    assert token == 'fromenv'


def test_resolve_settings_token_enforced_on_loopback(monkeypatch):
    monkeypatch.setattr(wa, 'load_settings',
                        lambda: {'web_console': {'token': 'sekret'}})
    monkeypatch.delenv('ASA_WEB_TOKEN', raising=False)
    host, token = wa.resolve_web_console()
    assert host == '127.0.0.1' and token == 'sekret'  # explicit token honored


def test_is_loopback():
    assert wa._is_loopback('127.0.0.1') and wa._is_loopback('localhost')
    assert not wa._is_loopback('0.0.0.0') and not wa._is_loopback('192.168.1.5')


# ── live gate via TestClient ───────────────────────────────────────────────────

def _client():
    pytest.importorskip('fastapi')
    pytest.importorskip('httpx')
    if not wa._FASTAPI_OK:
        pytest.skip('fastapi not importable in web_app')
    from fastapi.testclient import TestClient
    return TestClient(wa.app)


def test_token_required_when_set(monkeypatch):
    client = _client()
    monkeypatch.setattr(wa, '_AUTH_TOKEN', 'sekret')

    # dashboard shell is public so the browser can load it and prompt for a token
    assert client.get('/').status_code == 200
    # a data endpoint is gated
    assert client.get('/jobs').status_code == 401
    assert client.get('/jobs',
                      headers={'Authorization': 'Bearer sekret'}).status_code == 200
    assert client.get('/jobs', params={'token': 'sekret'}).status_code == 200
    assert client.get('/jobs',
                      headers={'Authorization': 'Bearer wrong'}).status_code == 401
    # a mutating endpoint (tool-run ingests into the stores) is gated too
    r = client.post('/missions/anything/tools/run', json={'tool': 'header_audit'})
    assert r.status_code == 401


def test_open_when_no_token(monkeypatch):
    client = _client()
    monkeypatch.setattr(wa, '_AUTH_TOKEN', '')
    assert client.get('/jobs').status_code == 200     # loopback single-user default
