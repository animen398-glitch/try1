"""Web console Company tier endpoints (remote/web_app.py, F-C4 web parity).

Pure helpers over core.company (roll-up + assign) plus the live HTTP endpoints
via TestClient. Projects live under a tmp tree; the endpoint's default base is
monkeypatched to that tree so the live tests are deterministic.
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


# ── pure helpers ─────────────────────────────────────────────────────────────────

def test_company_view_rolls_up(tmp_path):
    _seed(tmp_path)
    ProjectStore(str(tmp_path)).assign('x.com', 'acme_corp')
    d = wa._company_view(base=str(tmp_path))
    assert 'error' not in d
    by_slug = {r['slug']: r for r in d['rows']}
    assert by_slug['acme_corp']['project_count'] == 1
    assert by_slug['acme_corp']['risk_level'] == 'High'
    assert by_slug['acme_corp']['warning_count'] == 1
    assert d['totals']['companies'] == 1
    assert d['totals']['warning_count'] == 1


def test_company_view_empty(tmp_path):
    d = wa._company_view(base=str(tmp_path))
    assert d['rows'] == [] and d['totals'].get('companies', 0) == 0


def test_company_assign_sets_and_clears(tmp_path):
    _seed(tmp_path)
    out = wa._company_assign('x.com', 'Acme Corp', base=str(tmp_path))
    assert out['status'] == 'ok' and out['company'] == 'acme_corp'
    assert ProjectStore(str(tmp_path)).get('x.com').get_company() == 'acme_corp'
    # Empty name unassigns.
    out = wa._company_assign('x.com', '', base=str(tmp_path))
    assert out['status'] == 'ok' and out['company'] is None
    assert ProjectStore(str(tmp_path)).get('x.com').get_company() is None


def test_company_assign_unknown_project(tmp_path):
    out = wa._company_assign('ghost.com', 'Acme', base=str(tmp_path))
    assert 'not found' in out['error']


# ── console surface ──────────────────────────────────────────────────────────────

def test_dashboard_exposes_companies():
    html = wa._DASHBOARD
    assert 'showCompanies()' in html and '/companies' in html


# ── live endpoints ───────────────────────────────────────────────────────────────

def test_company_endpoints_with_testclient(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    _seed(tmp_path)
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    client = TestClient(wa.app)

    # Assign, then the roll-up reflects it.
    r = client.post('/projects/x.com/company', json={'name': 'Acme Corp'})
    assert r.status_code == 200 and r.json()['company'] == 'acme_corp'

    r = client.get('/companies')
    assert r.status_code == 200
    body = r.json()
    by_slug = {c['slug']: c for c in body['rows']}
    assert by_slug['acme_corp']['project_count'] == 1

    # Unknown project → 404.
    r = client.post('/projects/ghost.com/company', json={'name': 'X'})
    assert r.status_code == 404
