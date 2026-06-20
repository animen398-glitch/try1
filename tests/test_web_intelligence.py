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


def test_exposure_view_ranks_assets():
    _seed('p')
    d = wa._exposure_view('p')
    assert 'error' not in d and d['summary']['assets'] >= 1
    # the ranking is exposure-descending; the top item carries a score
    assert d['items'][0]['exposure'] >= d['items'][-1]['exposure']


def test_criticality_and_paths_no_project_is_empty():
    assert wa._criticality_view(None)['items'] == []
    assert wa._attack_paths_view(None)['paths'] == []
    assert wa._exposure_view(None)['items'] == []


def test_dashboard_exposes_criticality_and_paths():
    html = wa._DASHBOARD
    assert 'showCriticality()' in html and '/criticality' in html
    assert 'showAttackPaths()' in html and '/attack-paths' in html
    assert 'showExposure()' in html and '/exposure' in html


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
    assert client.get('/exposure', params={'project': 'p'}).status_code == 200


# ── Scan Accuracy web parity (MODULE 1) ───────────────────────────────────────

def _seed_accuracy_project(base):
    """A project with a scan report (technology + infra) under ``base`` plus a
    finding + asset in the stores, so accuracy_from_report scores entities."""
    import json

    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    from core.project import ProjectStore
    project = ProjectStore(base).get_or_create('https://acme.com')
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {'scan_id': sid, 'phases': {'recon': {'status': 'Success', 'data': {
        'technologies': [{'name': 'nginx', 'version': '1.18',
                          'evidence_method': 'header', 'source': 'header'}],
        'infrastructure': {'asn': 'AS1', 'ip': '1.2.3.4', 'source': 'rdap'}}}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)
    FindingsStore().sync('acme.com', 's1', [
        {'category': 'vuln', 'severity': 'high', 'title': 'X',
         'location': 'a.acme.com/x'}])
    AssetStore().sync('acme.com', sid, [Asset('domain', 'acme.com')])
    return 'acme.com'


def test_accuracy_view_scores_entities(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    slug = _seed_accuracy_project(str(tmp_path))
    d = wa._accuracy_view(slug)
    assert 'error' not in d
    assert d['summary']['entities'] >= 1
    types = {i['entity_type'] for i in d['items']}
    assert 'technology' in types          # report phase entity surfaced


def test_accuracy_view_no_project_is_empty():
    assert wa._accuracy_view(None)['items'] == []


def test_accuracy_view_unknown_project_errors():
    assert 'error' in wa._accuracy_view('definitely-not-a-project-xyz')


def test_dashboard_exposes_accuracy():
    html = wa._DASHBOARD
    assert 'showAccuracy()' in html and '/accuracy' in html


def test_accuracy_endpoint_with_testclient(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    slug = _seed_accuracy_project(str(tmp_path))
    client = TestClient(wa.app)
    r = client.get('/accuracy', params={'project': slug})
    assert r.status_code == 200
    assert r.json()['summary']['entities'] >= 1


# ── Technology Risk web parity (EPIC 15) ──────────────────────────────────────

def _seed_tech_risk_project(base):
    """A project whose latest report carries recon data with an outdated tech and a
    vulnerable JS dependency, so build_technology_risk produces items."""
    import json

    from core.project import ProjectStore
    project = ProjectStore(base).get_or_create('https://acme.com')
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {'scan_id': sid, 'phases': {'recon': {'status': 'Success', 'data': {
        'technologies': [{'name': 'PHP', 'version': '5.6', 'category': 'Language'}],
        'dependencies': {'libraries': [
            {'name': 'jquery', 'library': 'jquery', 'version': '1.7.0',
             'vulnerabilities': [{'cve': 'CVE-X', 'severity': 'high'}]}]}}}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)
    return 'acme.com'


def test_technology_risk_view_scores_items(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    slug = _seed_tech_risk_project(str(tmp_path))
    d = wa._technology_risk_view(slug)
    assert 'error' not in d
    assert d['summary']['items'] >= 2
    kinds = {i['kind'] for i in d['items']}
    assert {'technology', 'dependency'} <= kinds


def test_technology_risk_view_no_project_is_empty():
    assert wa._technology_risk_view(None)['items'] == []


def test_technology_risk_view_unknown_project_errors():
    assert 'error' in wa._technology_risk_view('definitely-not-a-project-xyz')


def test_dashboard_exposes_technology_risk():
    html = wa._DASHBOARD
    assert 'showTechnologyRisk()' in html and '/technology-risk' in html


def test_technology_risk_endpoint_with_testclient(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    slug = _seed_tech_risk_project(str(tmp_path))
    client = TestClient(wa.app)
    r = client.get('/technology-risk', params={'project': slug})
    assert r.status_code == 200
    assert r.json()['summary']['items'] >= 2


# ── Related Assets web parity (infra-chain tail) ──────────────────────────────

def _seed_related_project(base):
    """A project whose latest report carries an asn_intel phase with reverse-IP
    neighbours (one of which is our own subdomain, to verify filtering)."""
    import json

    from core.project import ProjectStore
    project = ProjectStore(base).get_or_create('https://acme.com')
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {'scan_id': sid, 'domain': 'acme.com', 'phases': {
        'subdomains': {'status': 'Success', 'data': {'results': [
            {'subdomain': 'api.acme.com'}]}},
        'asn_intel': {'status': 'Success', 'data': {
            'ip': '1.2.3.4', 'neighbor_count': 3,
            'neighbors': ['api.acme.com', 'acme.com', 'stranger.org']}}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)
    return 'acme.com'


def test_related_assets_view_filters_own_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    slug = _seed_related_project(str(tmp_path))
    d = wa._related_assets_view(slug)
    assert 'error' not in d and d['shared_ip'] == '1.2.3.4'
    assert [r['host'] for r in d['related']] == ['stranger.org']   # own filtered
    assert d['count'] == 1 and d['total'] == 3


def test_related_assets_view_no_project_is_empty():
    assert wa._related_assets_view(None)['related'] == []


def test_dashboard_exposes_related_assets():
    html = wa._DASHBOARD
    assert 'showRelatedAssets()' in html and '/related-assets' in html


def test_related_assets_endpoint_with_testclient(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    monkeypatch.setattr(wa, '_REPORT_BASE', tmp_path)
    slug = _seed_related_project(str(tmp_path))
    client = TestClient(wa.app)
    r = client.get('/related-assets', params={'project': slug})
    assert r.status_code == 200
    assert r.json()['count'] == 1
