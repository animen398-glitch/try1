"""Web console Overview endpoint (remote/web_app.py, F5 web parity).

A pure helper over core.portfolio plus the live HTTP endpoint via TestClient.
Projects live under a tmp tree; the endpoint's default base is monkeypatched to
that tree so the live test is deterministic (it otherwise reads the server's
real SiteAnalyzer workspace).
"""

import json

import pytest

import remote.web_app as wa
from core.project import ProjectStore


def _seed(base):
    project = ProjectStore(base).get_or_create('https://x.com')
    for i, score in enumerate((10, 60)):
        sid = f'2026010{i + 1}_000000'
        scan_dir = project.start_scan(sid)
        report = {
            'scan_id': sid, 'finished_at': sid,
            'warnings': ([{'stage': 'evidence', 'message': 'manifest failed'}]
                         if score >= 50 else []),
            'executive_summary': {
                'risk_level': 'High' if score >= 50 else 'Low',
                'risk_score': score,
                'metrics': {'attack_surface_score': score // 2,
                            'secrets': 1 if score >= 50 else 0,
                            'high': 2 if score >= 50 else 0, 'medium': 1},
            },
        }
        (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        project.record_scan(scan_dir, report)
    return base


# ── pure helper ──────────────────────────────────────────────────────────────────

def test_overview_summary_reads_portfolio(tmp_path):
    _seed(tmp_path)
    d = wa._overview_summary(base=str(tmp_path))
    assert 'error' not in d
    assert d['totals']['projects'] == 1
    row = d['rows'][0]
    assert row['slug'] == 'x.com' and row['risk_level'] == 'High'
    assert row['risk_delta'] == 50
    assert row['warning_count'] == 1
    assert row['warning_stages'] == 'evidence'
    assert row['warning_summary'][0]['message'] == 'manifest failed'
    assert d['totals']['warning_count'] == 1


def test_overview_summary_empty(tmp_path):
    d = wa._overview_summary(base=str(tmp_path))
    assert d['rows'] == [] and d['totals']['projects'] == 0


# ── console surface ──────────────────────────────────────────────────────────────

def test_dashboard_exposes_overview():
    html = wa._DASHBOARD
    assert 'showOverview()' in html and '/overview' in html
    assert 'warnings: ' in html
    assert 'warning_stages' in html


# ── live endpoint ────────────────────────────────────────────────────────────────

def test_overview_endpoint_with_testclient(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    client = TestClient(wa.app)

    r = client.get('/overview')
    assert r.status_code == 200
    body = r.json()
    assert body['totals']['projects'] == 1
    assert body['totals']['warning_count'] == 1
    assert body['rows'][0]['slug'] == 'x.com'
