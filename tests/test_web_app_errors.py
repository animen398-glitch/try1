"""Error/exit contract for the LAN web console (remote.web_app).

Offline: uses FastAPI's TestClient; no real network or engines run. Verifies
that every failure path yields a uniform JSON envelope and the documented
status codes, and that the job registry stays consistent with /jobs.
"""
import pytest

pytest.importorskip('fastapi')
from fastapi.testclient import TestClient  # noqa: E402

import remote.web_app as web  # noqa: E402


@pytest.fixture()
def client():
    # raise_server_exceptions=False so the global 500 handler's JSON response is
    # returned to the test instead of re-raised.
    return TestClient(web.app, raise_server_exceptions=False)


def test_jobs_endpoint_matches_registry(client):
    r = client.get('/jobs')
    assert r.status_code == 200
    names = {j['name'] for j in r.json()}
    assert names == set(web.JOBS)
    assert all(callable(web.JOBS[n]['fn']) for n in web.JOBS)


def test_run_unknown_job_is_404_json(client):
    r = client.post('/run/does-not-exist', json={'url': 'http://x'})
    assert r.status_code == 404
    assert 'unknown job' in r.json()['error']


def test_run_missing_url_is_422(client):
    r = client.post('/run/recon', json={})
    assert r.status_code == 422  # pydantic validation, FastAPI's own contract


def test_run_when_busy_is_409(client, monkeypatch):
    monkeypatch.setattr(web, '_active_job', 'recon')
    r = client.post('/run/recon', json={'url': 'http://x'})
    assert r.status_code == 409
    assert 'already running' in r.json()['error']


def test_monitor_enable_bad_interval_is_400(client):
    r = client.post('/monitor/enable',
                    json={'url': 'http://x', 'interval': 'hourly'})
    assert r.status_code == 400
    assert 'interval' in r.json()['error']


def test_unhandled_exception_returns_json_500(client, monkeypatch):
    """An endpoint whose engine raises still returns a JSON error envelope,
    not Starlette's plain-text 500 (the console always does response.json())."""
    def boom(*a, **k):
        raise RuntimeError('kaboom')

    monkeypatch.setattr(web.monitor, 'status', boom)
    r = client.get('/monitor')
    assert r.status_code == 500
    body = r.json()
    assert 'kaboom' in body['error']


def test_report_traversal_is_404(client):
    r = client.get('/report', params={'file': '../../etc/passwd'})
    assert r.status_code == 404
    assert 'error' in r.json()
