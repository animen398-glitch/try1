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


def test_tool_runs_csv_endpoint(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient

    from core import pentest_mission as pm
    from core.tool_runner import run_tool_for_mission, tool_scan_id
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)

    # ingest a tool run for the project (header_audit, in-scope ROE)
    mission = pm.create_mission(
        'x.com', 'review',
        roe={'allowed_domains': ['x.com'], 'active_scan_enabled': True,
             'passive_only': False, 'authorized_by': 'client'},
        allowed_actions=['headers_check'])
    out = run_tool_for_mission(
        mission, 'header_audit', {'url': 'https://x.com', 'headers': {}},
        scan_id=tool_scan_id('header_audit'))
    assert out['ingest']['written']

    client = TestClient(wa.app)
    r = client.get('/tool-runs.csv', params={'project': 'x.com'})
    assert r.status_code == 200
    assert r.headers['content-type'].startswith('text/csv')
    lines = r.text.splitlines()
    assert lines[0].startswith('When,Tool,Findings,Assets')
    assert any('header_audit' in ln for ln in lines[1:])


def test_retest_runs_csv_endpoint(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient

    from core import engagement as eng
    from core.findings_adapter import Finding
    from core.findings_store import FindingsStore
    from core.retest_runner import run_retest
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)

    fid = FindingsStore().upsert('x.com', Finding(
        category='vuln', rule_id='r', title='t', severity='high',
        location='https://x.com/a').to_store(), scan_id='s1')['finding']['id']
    e = eng.link_finding(eng.create_engagement('Acme', 'x.com'), fid)
    run_retest(e, now='2026-07-01T10:00:00Z')

    client = TestClient(wa.app)
    r = client.get('/retest-runs.csv', params={'project': 'x.com'})
    assert r.status_code == 200
    assert r.headers['content-type'].startswith('text/csv')
    lines = r.text.splitlines()
    assert lines[0].startswith('When,Engagement,Status,Fixed')
    assert any(e['engagement_id'] in ln for ln in lines[1:])
