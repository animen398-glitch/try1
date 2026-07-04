"""Web console project-compare endpoint (remote/web_app.py).

A pure helper over core.project_compare plus the live HTTP endpoint via
TestClient. Two projects live under a tmp tree; the endpoint's default base is
monkeypatched to that tree so the live test is deterministic.
"""

import json

import pytest

import remote.web_app as wa
from core.project import ProjectStore


def _seed_project(base, slug_url, risk):
    project = ProjectStore(base).get_or_create(slug_url)
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {'scan_id': sid, 'finished_at': sid,
              'executive_summary': {'risk_level': 'High' if risk >= 50 else 'Low',
                                    'risk_score': risk,
                                    'metrics': {'high': 2 if risk >= 50 else 0}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)


def _seed(base):
    _seed_project(base, 'https://low.com', 15)
    _seed_project(base, 'https://high.com', 65)


# ── pure helper ──────────────────────────────────────────────────────────────────

def test_project_compare_helper(tmp_path):
    _seed(tmp_path)
    out = wa._project_compare('low.com', 'high.com', base=str(tmp_path))
    assert 'error' not in out
    assert out['a']['slug'] == 'low.com' and out['b']['slug'] == 'high.com'
    rs = {m['key']: m for m in out['metrics']}['risk_score']
    assert rs['a'] == 15 and rs['b'] == 65 and rs['worse'] == 'b'


def test_project_compare_helper_unknown_slug(tmp_path):
    _seed(tmp_path)
    out = wa._project_compare('low.com', 'ghost.com', base=str(tmp_path))
    assert 'not found' in out['error']


# ── live endpoint ────────────────────────────────────────────────────────────────

def test_project_compare_endpoint(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    client = TestClient(wa.app)

    r = client.get('/projects/compare', params={'a': 'low.com', 'b': 'high.com'})
    assert r.status_code == 200
    body = r.json()
    assert body['b']['risk_level'] == 'High'
    assert body['summary']['b_worse'] >= 1

    # unknown project → 404
    r404 = client.get('/projects/compare', params={'a': 'low.com', 'b': 'ghost.com'})
    assert r404.status_code == 404
