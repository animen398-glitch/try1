"""Web console Timeline endpoint (remote/web_app.py, F2 web parity).

A pure helper over core.timeline plus the live HTTP endpoint via TestClient.
Projects live under a tmp tree; the endpoint's default base (_REPORT_BASE) is
monkeypatched to it so the test is deterministic (it otherwise reads the
server's real SiteAnalyzer workspace).
"""

import json

import pytest

import remote.web_app as wa
from core.project import ProjectStore


def _seed(base):
    project = ProjectStore(base).get_or_create('https://x.com')
    # Two scans with a structural change (a new subdomain) → a timeline event.
    for i, subs in enumerate(([{'subdomain': 'a.x.com'}],
                              [{'subdomain': 'a.x.com'}, {'subdomain': 'b.x.com'}])):
        sid = f'2026010{i + 1}_000000'
        scan_dir = project.start_scan(sid)
        report = {
            'scan_id': sid, 'finished_at': sid, 'started_at': sid,
            'phases': {'subdomains': {'status': 'Success',
                                      'data': {'results': subs}}},
            'executive_summary': {'risk_level': 'Low', 'risk_100': (i + 1) * 4,
                                  'risk_score': i + 1,
                                  'metrics': {'risk_100': (i + 1) * 4}},
        }
        (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        project.record_scan(scan_dir, report)
    return base


# ── pure helper ──────────────────────────────────────────────────────────────────

def test_timeline_view_for_project(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    d = wa._timeline_view('x.com')
    assert 'error' not in d
    assert len(d['series']) == 2
    assert 'new_subdomain' in [e['type'] for e in d['events']]
    # EPIC 4: per-metric trend summary derived from the series.
    assert 'risk_score' in d['trend'] and d['trend']['risk_score']['n'] == 2


def test_timeline_view_no_project_is_empty():
    d = wa._timeline_view(None)
    assert d['series'] == [] and d['events'] == []


def test_timeline_view_unknown_project(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    d = wa._timeline_view('nope.com')
    assert d['events'] == [] and 'not found' in d.get('error', '')


# ── console surface ──────────────────────────────────────────────────────────────

def test_dashboard_exposes_timeline():
    html = wa._DASHBOARD
    assert 'showTimeline()' in html and '/timeline' in html


# ── live endpoint ────────────────────────────────────────────────────────────────

def test_timeline_endpoint_with_testclient(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    client = TestClient(wa.app)

    r = client.get('/timeline', params={'project': 'x.com'})
    assert r.status_code == 200
    body = r.json()
    assert len(body['series']) == 2
    assert any(e['type'] == 'new_subdomain' for e in body['events'])
