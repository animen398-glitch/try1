"""Tests for CollectionRunner pure helpers (no pipeline / network)."""

import json
from pathlib import Path

from core.collection_runner import CollectionRunner, _domain_slug


def test_domain_slug_normalizes():
    assert _domain_slug("https://www.Example.com/path") == "Example.com"
    assert _domain_slug("http://sub.example.org:8080") == "sub.example.org_8080"
    assert _domain_slug("not a url") == "not_a_url"


def test_cancel_sets_event():
    r = CollectionRunner()
    assert not r._cancel.is_set()
    r.cancel()
    assert r._cancel.is_set()
    report = {}
    assert r._cancelled(report) is True
    assert report["cancelled"] is True


def test_default_collection_has_subdomains_off():
    assert CollectionRunner().subdomains is False


def test_phase_subdomains_wraps_scanner_result(tmp_path, monkeypatch):
    """The phase shapes the scanner output as {summary, results} so the risk
    engine finds takeover_candidates and Scan Diff finds the host list."""
    from core.subdomain_scanner import SubdomainScanner
    monkeypatch.setattr(
        SubdomainScanner, "scan",
        lambda self, host, **kw: {
            "status": "Success", "domain": host, "total": 2,
            "live_count": 1, "takeover_candidates": ["bad.x.com"],
            "results": [{"subdomain": "bad.x.com", "takeover": True},
                        {"subdomain": "ok.x.com"}]})
    r = CollectionRunner(subdomains=True)
    phase = r._phase_subdomains("https://x.com", tmp_path)

    assert phase["status"] == "Success"
    # Shape the unified risk engine already reads (P3): data.summary.takeover…
    assert phase["data"]["summary"]["takeover_candidates"] == ["bad.x.com"]
    assert {e["subdomain"] for e in phase["data"]["results"]} == {
        "bad.x.com", "ok.x.com"}
    # Artefact written for the scan directory.
    assert (tmp_path / "subdomains" / "subdomains.json").exists()


def test_render_html_subdomains_card_flags_takeover():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"subdomains": {"status": "Success", "data": {
            "summary": {"total": 2, "takeover_candidates": ["bad.x.com"]},
            "results": [{"subdomain": "bad.x.com", "takeover": True},
                        {"subdomain": "ok.x.com"}]}}},
    }
    html = r._render_html(report)
    assert "Subdomains" in html
    assert "bad.x.com" in html and "ok.x.com" in html
    assert "takeover" in html
    assert "<script" not in html.lower()


def test_render_html_certificate_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"certificate": {"status": "Success", "data": {
            "subject": "x.com", "issuer": "R3 (Let's Encrypt)",
            "not_after": "Aug 1 2026", "fingerprint_sha256": "a" * 64}}},
    }
    html = r._render_html(report)
    assert "TLS Certificate" in html
    assert "x.com" in html and "Let&#x27;s Encrypt" in html  # issuer escaped
    assert "Aug 1 2026" in html
    assert "<script" not in html.lower()


def test_default_collection_has_security_off():
    assert CollectionRunner().security is False


def test_phase_security_writes_artifact(tmp_path, monkeypatch):
    """The opt-in security phase wraps SecurityAuditor.audit and stores the
    result at phases.security.data — the shape risk/surface/diff already read."""
    from core.security_auditor import SecurityAuditor
    audit_result = {
        'status': 'Success', 'url': 'https://x.com', 'secrets': [],
        'source_maps': [{'url': 'https://x.com/app.js.map', 'has_content': True}],
        'graphql': [{'url': 'https://x.com/graphql', 'graphql': True,
                     'introspection': True}],
        'summary': {'maps_with_content': 1, 'graphql': 1,
                    'graphql_introspection': 1},
    }
    monkeypatch.setattr(SecurityAuditor, 'audit', lambda self, url: audit_result)
    r = CollectionRunner(security=True)
    report = {'phases': {'vulns': {'status': 'Success', 'findings': [],
                                   'summary': {}}}}
    phase = r._phase_security('https://x.com', tmp_path, report)

    assert phase['status'] == 'Success'
    assert phase['data']['summary']['maps_with_content'] == 1
    assert phase['data']['summary']['graphql_introspection'] == 1
    assert (tmp_path / 'security' / 'audit.json').exists()

    # The risk-bearing exposures are folded into the vuln phase as findings, so
    # they live through Findings Management and score via their severity.
    folded = report['phases']['vulns']['findings']
    cats = {f['category'] for f in folded}
    assert cats == {'sourcemap', 'graphql'}
    smap = next(f for f in folded if f['category'] == 'sourcemap')
    assert smap['severity'] == 'High' and smap['location'] == 'https://x.com/app.js.map'
    gql = next(f for f in folded if f['category'] == 'graphql')
    assert gql['severity'] == 'High'   # introspection on -> High
    # Summary recomputed over the folded findings (2 High).
    assert report['phases']['vulns']['summary']['high'] == 2


def test_security_findings_reachable_graphql_is_info():
    # A merely reachable GraphQL API (introspection off) is a managed Info
    # finding; a leaking map and an open schema are High.
    data = {
        'source_maps': [{'url': 'https://x/a.map', 'has_content': True},
                        {'url': 'https://x/b.map', 'has_content': False}],
        'graphql': [{'url': 'https://x/g1', 'graphql': True, 'introspection': False},
                    {'url': 'https://x/g2', 'graphql': False}],
    }
    found = CollectionRunner._security_findings(data)
    by_loc = {f['location']: f for f in found}
    assert set(by_loc) == {'https://x/a.map', 'https://x/g1'}  # non-leaking dropped
    assert by_loc['https://x/a.map']['severity'] == 'High'
    assert by_loc['https://x/g1']['severity'] == 'Info'


def test_security_findings_fold_audit_secrets():
    # Secrets the deep-JS audit finds become High secret findings (source
    # 'secret-audit', located at the script URL); placeholders are dropped and no
    # plaintext leaks. They share the shape of api-phase secrets (dedup by id).
    data = {
        'source_maps': [], 'graphql': [],
        'secrets': [
            {'type': 'AWS Access Key', 'match': 'AKIAIOSFODNN7EXAMPLE',
             'source': 'https://x.com/app.js'},
            {'type': 'Generic API Key', 'match': 'your_api_key_here',
             'source': 'https://x.com/app.js'}],          # placeholder → dropped
    }
    found = CollectionRunner._security_findings(data)
    secrets = [f for f in found if f['category'] == 'secret']
    assert len(secrets) == 1
    s = secrets[0]
    assert s['severity'] == 'High' and s['source'] == 'secret-audit'
    assert s['location'] == 'https://x.com/app.js'
    assert 'AKIAIOSFODNN7EXAMPLE' not in str(s)          # no plaintext


def test_takeover_findings_are_high_and_host_located():
    # Each takeover candidate becomes a High finding keyed by its host, with the
    # canonical category so Findings Management / risk count it once.
    report = {'phases': {'subdomains': {'data': {'summary': {
        'takeover_candidates': ['bad.x.com', {'subdomain': 'evil.x.com'}, '']}}}}}
    found = CollectionRunner._takeover_findings(report)
    by_loc = {f['location']: f for f in found}
    assert set(by_loc) == {'bad.x.com', 'evil.x.com'}     # blank dropped
    assert all(f['severity'] == 'High' for f in found)
    assert all(f['category'] == 'takeover' for f in found)


def test_takeover_findings_empty_without_subdomain_phase():
    assert CollectionRunner._takeover_findings({'phases': {}}) == []


def test_secret_findings_are_high_with_nonleaking_identity():
    # Plausible keys become High secret findings; placeholders are dropped; the
    # plaintext never appears (only a masked discriminator/detail).
    report = {'url': 'https://x.com', 'phases': {'api': {'data': {'details': {
        'AWS Access Key': ['AKIAIOSFODNN7EXAMPLE'],
        'Generic API Key': ['your_api_key_here']}}}}}
    found = CollectionRunner._secret_findings(report)
    assert len(found) == 1                                 # placeholder dropped
    f = found[0]
    assert f['severity'] == 'High' and f['category'] == 'secret'
    assert f['location'] == 'https://x.com'
    assert f['source'] == 'secret' and f['discriminator']
    # No plaintext anywhere in the finding.
    assert 'AKIAIOSFODNN7EXAMPLE' not in str(f)


def test_secret_findings_empty_without_api_details():
    assert CollectionRunner._secret_findings({'phases': {}}) == []


def test_render_html_security_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"security": {"status": "Success", "data": {
            "source_maps": [
                {"url": "https://x/app.js.map", "has_content": True},
                {"url": "https://x/vendor.js.map", "has_content": False}],
            "graphql": [
                {"url": "https://x/graphql", "graphql": True,
                 "introspection": True},
                {"url": "https://x/none", "graphql": False}],
            "summary": {"maps_with_content": 1, "graphql": 1,
                        "graphql_introspection": 1}}}},
    }
    html = r._render_html(report)
    assert "Security Audit" in html
    # Leaking map surfaced; the non-leaking one is not listed.
    assert "app.js.map" in html and "vendor.js.map" not in html
    # Reachable GraphQL surfaced with the introspection flag.
    assert "x/graphql" in html and "introspection" in html
    assert "<script" not in html.lower()


def test_phase_openapi_writes_artifact(tmp_path, monkeypatch):
    """The opt-in OpenAPI phase wraps discover() and writes openapi.json."""
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_openapi", lambda url: {
        "status": "Success", "spec_url": f"{url}/openapi.json",
        "version": "3.0.0", "title": "API", "servers": [],
        "endpoints": [{"method": "GET", "path": "/u"}],
        "counts": {"paths": 1, "endpoints": 1}})
    r = CollectionRunner(openapi=True)
    phase = r._phase_openapi("https://x.com", tmp_path)
    assert phase["status"] == "Success"
    assert phase["data"]["counts"]["endpoints"] == 1
    assert (tmp_path / "openapi" / "openapi.json").exists()


def test_phase_openapi_not_found_is_clean(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_openapi", lambda url: {
        "status": "Not found", "spec_url": None, "endpoints": [],
        "counts": {"paths": 0, "endpoints": 0}})
    phase = CollectionRunner(openapi=True)._phase_openapi("https://x.com", tmp_path)
    assert phase["status"] == "Not found"
    assert not (tmp_path / "openapi" / "openapi.json").exists()


def test_render_html_openapi_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"openapi": {"status": "Success", "data": {
            "status": "Success", "spec_url": "https://x/openapi.json",
            "version": "3.0.0", "title": "Demo", "servers": [],
            "endpoints": [{"method": "GET", "path": "/users", "summary": "List",
                           "tags": [], "deprecated": False, "params": 0}],
            "counts": {"paths": 1, "endpoints": 1}}}},
    }
    html = r._render_html(report)
    assert "OpenAPI / API Map" in html and "/users" in html
    assert "<script" not in html.lower()


def test_phase_historical_writes_artifact(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_historical", lambda url: {
        "status": "Success", "source": "wayback", "domain": "x.com",
        "total": 3, "categories": {"admin": ["https://x.com/admin"]},
        "interesting": ["https://x.com/admin"]})
    r = CollectionRunner(historical=True)
    phase = r._phase_historical("https://x.com", tmp_path)
    assert phase["status"] == "Success"
    assert phase["data"]["total"] == 3
    assert (tmp_path / "historical" / "historical.json").exists()


def test_render_html_historical_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"historical": {"status": "Success", "data": {
            "status": "Success", "source": "wayback", "total": 2,
            "categories": {"admin": ["https://x/admin"]},
            "interesting": ["https://x/admin"]}}},
    }
    html = r._render_html(report)
    assert "Historical URLs" in html and "/admin" in html
    assert "<script" not in html.lower()


def test_phase_dns_folds_findings_into_vulns(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_dns", lambda url: {
        "status": "Success", "domain": "x.com",
        "records": {"A": ["1.2.3.4"]},
        "email_auth": {"spf": None, "dmarc": None, "dkim_selectors": [],
                       "caa": False},
        "findings": [{"severity": "Medium", "title": "No SPF record",
                      "source": "dns"}]})
    r = CollectionRunner(dns=True)
    report = {"url": "https://x.com", "phases": {"vulns": {
        "status": "Success", "findings": [], "summary": {"high": 0, "medium": 0,
                                                          "info": 0}}}}
    phase = r._phase_dns("https://x.com", tmp_path, report)
    assert phase["status"] == "Success"
    assert (tmp_path / "dns" / "dns.json").exists()
    # finding folded into the vuln phase so the risk engine sees it
    titles = [f["title"] for f in report["phases"]["vulns"]["findings"]]
    assert "No SPF record" in titles
    assert report["phases"]["vulns"]["summary"]["medium"] == 1


def test_render_html_dns_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"dns": {"status": "Success", "data": {
            "status": "Success", "records": {"A": ["1.2.3.4"], "MX": [],
                                             "TXT": [], "AAAA": [], "NS": [],
                                             "CAA": []},
            "email_auth": {"spf": "v=spf1 ~all", "dmarc": "reject",
                           "dkim_selectors": ["google"], "caa": True},
            "findings": []}}},
    }
    html = r._render_html(report)
    assert "DNS / Email Auth" in html and "1.2.3.4" in html
    assert "<script" not in html.lower()


def test_phase_emails_writes_artifact(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_emails", lambda url: {
        "status": "Success", "domain": "x.com", "sources": ["homepage"],
        "total": 2, "on_domain": ["info@x.com"], "external": ["ceo@gmail.com"],
        "roles": {"info": ["info@x.com"], "personal": ["ceo@gmail.com"]}})
    r = CollectionRunner(emails=True)
    phase = r._phase_emails("https://x.com", tmp_path)
    assert phase["status"] == "Success" and phase["data"]["total"] == 2
    assert (tmp_path / "emails" / "emails.json").exists()


def test_render_html_emails_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"emails": {"status": "Success", "data": {
            "status": "Success", "total": 1, "sources": ["homepage"],
            "on_domain": ["info@x.com"], "external": [],
            "roles": {"info": ["info@x.com"]}}}},
    }
    html = r._render_html(report)
    assert "Email Intelligence" in html and "info@x.com" in html
    assert "<script" not in html.lower()


def test_phase_employees_writes_artifact(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_employees", lambda url: {
        "status": "Success", "domain": "x.com", "sources": ["/team"],
        "total": 1, "with_email": 1, "format": "{first}.{last}",
        "people": [{"name": "Jane Smith", "title": "CTO",
                    "email": "jane.smith@x.com", "email_source": "found",
                    "social": []}]})
    r = CollectionRunner(employees=True)
    phase = r._phase_employees("https://x.com", tmp_path)
    assert phase["status"] == "Success" and phase["data"]["total"] == 1
    assert (tmp_path / "employees" / "employees.json").exists()


def test_render_html_employees_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"employees": {"status": "Success", "data": {
            "status": "Success", "total": 1, "with_email": 1,
            "format": "{first}.{last}", "sources": ["/team"],
            "people": [{"name": "Jane Smith", "title": "CTO",
                        "email": "jane.smith@x.com", "email_source": "found",
                        "social": []}]}}},
    }
    html = r._render_html(report)
    assert "Employee Intelligence" in html and "Jane Smith" in html
    assert "<script" not in html.lower()


def test_phase_ct_writes_artifact(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, "discover_ct", lambda url: {
        "status": "Success", "domain": "x.com", "total_certs": 2,
        "name_count": 2, "names": ["x.com", "www.x.com"],
        "issuers": [{"ca": "Let's Encrypt", "count": 2}],
        "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-05-01T00:00:00",
        "recent_count": 1, "active_count": 1, "expired_count": 1,
        "wildcards": [], "certs": [{"id": 1, "issuer": "Let's Encrypt",
                                    "not_before": "2024-05-01T00:00:00",
                                    "not_after": "2024-08-01T00:00:00",
                                    "names": ["x.com"], "wildcard": False}]})
    r = CollectionRunner(ct=True)
    phase = r._phase_ct("https://x.com", tmp_path)
    assert phase["status"] == "Success" and phase["data"]["total_certs"] == 2
    assert (tmp_path / "ct" / "ct_history.json").exists()


def test_render_html_ct_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"ct": {"status": "Success", "data": {
            "status": "Success", "total_certs": 1, "name_count": 1,
            "names": ["x.com"], "issuers": [{"ca": "Let's Encrypt", "count": 1}],
            "first_seen": "2024-05-01T00:00:00", "last_seen": "2024-05-01T00:00:00",
            "recent_count": 1, "active_count": 1, "expired_count": 0,
            "wildcards": [], "certs": [{"id": 1, "issuer": "Let's Encrypt",
                                        "not_before": "2024-05-01T00:00:00",
                                        "not_after": "2024-08-01T00:00:00",
                                        "names": ["x.com"], "wildcard": False}]}}},
    }
    html = r._render_html(report)
    assert "Certificate Transparency" in html and "Encrypt" in html
    assert "<script" not in html.lower()


def test_sync_findings_persists_and_stamps_status(tmp_path):
    # The findings DB is isolated to a tmp file by the autouse conftest fixture.
    from core.project import ProjectStore
    from core.findings_store import FindingsStore

    project = ProjectStore(tmp_path).get_or_create("https://x.com")
    report = {"phases": {"vulns": {"status": "Success", "findings": [
        {"title": "Site served over plain HTTP (not HTTPS)", "severity": "High"},
        {"title": "Weak Content-Security-Policy", "severity": "Medium"}]}}}
    r = CollectionRunner()
    r._sync_findings(report, project, "s1")
    # Findings stamped with stored status; report carries the delta summary.
    assert all("status" in f for f in report["phases"]["vulns"]["findings"])
    assert report["findings"]["summary"]["total"] == 2
    assert report["findings"]["new"] == 2
    assert FindingsStore().summary(project.slug)["active"] == 2


def test_render_findings_card():
    r = CollectionRunner()
    fdata = {"project": "x.com", "new": 1, "reopened": 0, "resolved": 2,
             "recurring": 3, "summary": {"total": 6, "active": 4,
             "by_status": {"OPEN": 4, "FIXED": 2}}}
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {}, "findings": fdata}
    html = r._render_html(report)
    assert "Findings Management" in html and "авто-исправлено" in html
    assert "<script" not in html.lower()


def test_render_assets_card():
    r = CollectionRunner()
    adata = {"project": "x.com", "new": 2, "gone": 1, "reappeared": 0,
             "recurring": 3, "summary": {"total": 6, "active": 5,
             "by_type": {"subdomain": 3, "ip": 2, "technology": 1}}}
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {}, "assets": adata}
    html = r._render_html(report)
    assert "Asset Inventory" in html and "исчезло" in html
    assert "subdomain" in html and "5/6 активных" in html
    assert "<script" not in html.lower()


def test_render_intelligence_card_shows_priorities():
    r = CollectionRunner()
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {},
              "intelligence": {
                  "summary": {"findings": 2, "top_priority": 45,
                              "high_confidence": 1},
                  "top": [{"title": "CVE-2021-1 in lib", "severity": "high",
                           "priority": 45, "confidence": 95,
                           "confidence_band": "high"}]}}
    html = r._render_html(report)
    assert "Priorities" in html
    assert "CVE-2021-1 in lib" in html and "conf 95%" in html
    assert "<script" not in html.lower()


def test_render_asset_graph_card_shows_clusters():
    r = CollectionRunner()
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {},
              "asset_graph": {
                  "summary": {"nodes": 9, "edges": 12, "clusters": 1},
                  "shared_infra": [{"type": "ip", "node": "1.2.3.4", "count": 3,
                                    "members": ["a.x.com", "b.x.com", "x.com"]}]}}
    html = r._render_html(report)
    assert "Asset Relationships" in html
    assert "1.2.3.4" in html and "3 актив" in html        # the cluster surfaced
    assert "<script" not in html.lower()


def test_render_asset_criticality_card_shows_top_assets():
    r = CollectionRunner()
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {},
              "asset_criticality": {
                  "summary": {"assets": 9, "high_criticality": 1,
                              "top_criticality": 78},
                  "top": [{"type": "ip", "value": "1.2.3.4", "criticality": 78,
                           "band": "high"}]}}
    html = r._render_html(report)
    assert "Asset Criticality" in html
    assert "1.2.3.4" in html and "78" in html and "high" in html
    assert "<script" not in html.lower()


def test_render_attack_paths_card_shows_lateral_route():
    r = CollectionRunner()
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {},
              "attack_paths": {
                  "summary": {"paths": 1, "critical_paths": 0, "top_score": 41},
                  "top": [{"pivot_type": "ip", "pivot_node": "1.2.3.4",
                           "entry": "a.x.com", "entry_severity": "critical",
                           "targets": ["b.x.com", "c.x.com"],
                           "critical_targets": 1, "score": 41, "band": "medium"}]}}
    html = r._render_html(report)
    assert "Attack Paths" in html
    assert "a.x.com" in html and "1.2.3.4" in html and "2 targets" in html
    assert "1 crit" in html
    assert "<script" not in html.lower()


def test_render_trends_card_shows_sparklines_for_multi_scan():
    r = CollectionRunner()
    trends = [
        {"scan_id": "s1", "risk_score": 4, "attack_surface": 10,
         "secrets": 0, "high": 1},
        {"scan_id": "s2", "risk_score": 12, "attack_surface": 18,
         "secrets": 2, "high": 3},
    ]
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {}, "trends": trends}
    html = r._render_html(report)
    assert "Trends" in html and "Risk score" in html
    assert "История за <b>2</b>" in html
    assert "<polyline" in html                      # an actual sparkline drawn
    assert "<script" not in html.lower()
    # EPIC 4: the risk-trend verdict line (rising 4 → 12, +8 since first scan).
    assert "рост" in html and "4 → 12" in html and "+8" in html


def test_render_trends_card_hidden_for_single_scan():
    r = CollectionRunner()
    report = {"url": "https://x", "domain": "x", "started_at": "",
              "finished_at": "", "project_dir": "", "phases": {},
              "trends": [{"scan_id": "s1", "risk_score": 4}]}
    html = r._render_html(report)
    # A single point is not a trend → no card.
    assert "Trends" not in html and "История за" not in html


def test_build_summary_excludes_inactive_findings():
    # The risk engine drops fixed/ignored/false-positive findings (status-aware).
    from core.executive_summary import build_summary
    findings = [
        {"title": "Plain HTTP", "severity": "High", "status": "OPEN"},
        {"title": "Weak CSP", "severity": "Medium", "status": "FIXED"},
        {"title": "CMS info", "severity": "Info", "status": "IGNORED"},
    ]
    report = {"phases": {"vulns": {"status": "Success", "findings": findings,
              "summary": {"high": 1, "medium": 1, "info": 1, "risk_score": 8}}}}
    summary = build_summary(report)
    assert summary["metrics"]["high"] == 1      # open High counts
    assert summary["metrics"]["medium"] == 0    # FIXED dropped
    assert summary["metrics"]["info"] == 0      # IGNORED dropped


def test_phase_subdomains_feeds_takeover_into_risk_engine(monkeypatch):
    # With a takeover candidate present, the executive summary escalates.
    from core.executive_summary import build_summary
    report = {"url": "https://x.com", "phases": {
        "subdomains": {"status": "Success", "data": {"summary": {
            "total": 1, "takeover_candidates": ["bad.x.com"]},
            "results": [{"subdomain": "bad.x.com", "takeover": True}]}}}}
    summary = build_summary(report)
    assert summary["metrics"]["takeovers"] == 1
    assert summary["risk_level"] == "Critical"      # a takeover forces Critical


def test_render_html_contains_phase_sections():
    r = CollectionRunner()
    report = {
        "url": "https://example.com",
        "domain": "example.com",
        "started_at": "2026-01-01T00:00:00",
        "finished_at": "2026-01-01T00:01:00",
        "project_dir": "/tmp/example.com_x",
        "phases": {
            "recon": {"status": "Success", "data": {"ip": "1.2.3.4", "cms": ["Nginx"],
                                                     "favicons": []}},
            "api": {"status": "Success", "data": {"keys_found": 2}},
            "capture": {"status": "Success", "data": {"pages_captured": 3, "errors": []}},
            "clone": {"status": "Skipped", "reason": "no captured pages"},
            "images": {"status": "Error", "error": "boom"},
        },
    }
    html = r._render_html(report)
    assert html.startswith("<!DOCTYPE html>")
    # Titles are HTML-escaped in the report ("&" -> "&amp;").
    for title in ("Recon &amp; Intel", "API Key Scan", "Capture (Frontend)",
                  "Clone (Frontend)", "Images (Media)"):
        assert title in html
    assert "Collection Report" in html
    assert "[Success]" in html and "[Skipped]" in html and "[Error]" in html


def test_render_html_includes_security_sections():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {
            "cookies": {"status": "Success", "data": {"total": 3, "weak": 1}},
            "vulns": {"status": "Success",
                      "summary": {"high": 1, "medium": 2, "info": 0, "risk_score": 9},
                      "findings": [{"severity": "High", "title": "Weak cookie sid"}]},
        },
    }
    html = r._render_html(report)
    assert "Cookie Security" in html
    assert "Vulnerabilities" in html
    assert "risk score" in html
    assert "Weak cookie sid" in html


def test_render_html_attack_surface_is_interactive_and_offline():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {
            "recon": {"status": "Success", "data": {"cms": ["Nginx"]}},
            "vulns": {"status": "Success", "summary": {},
                      "findings": [{"severity": "High", "title": "Exposed .env"}]},
        },
    }
    html = r._render_html(report)
    assert "Attack Surface" in html
    # The graph is now the interactive (CSS :target) form, still offline.
    assert 'class="as-wrap"' in html
    assert '.as-panel:target{display:block;}' in html
    assert 'href="#as-findings"' in html and 'id="as-findings"' in html
    # No JavaScript anywhere in the report (offline contract I2).
    assert "<script" not in html.lower()


def test_run_writes_scan_into_project_workspace(tmp_path, monkeypatch):
    """run() nests the scan under Projects/<slug>/scans/<id>/ and indexes it in
    metadata.json — with every network phase stubbed (fully offline)."""
    r = CollectionRunner()

    # Stub each phase so no network/Qt is touched; minimal canned data.
    monkeypatch.setattr(r, '_phase_recon',
                        lambda url, d: {'status': 'Success',
                                        'data': {'ip': '1.2.3.4', 'cms': []}})
    monkeypatch.setattr(r, '_phase_api',
                        lambda url, d: {'status': 'Success',
                                        'data': {'keys_found': 0}})
    monkeypatch.setattr(r, '_phase_capture',
                        lambda url, d: {'status': 'Success',
                                        'data': {'pages_captured': 0, 'errors': []}})
    monkeypatch.setattr(r, '_phase_images',
                        lambda url, d: {'status': 'Skipped'})
    monkeypatch.setattr(r, '_phase_cookies',
                        lambda url, d: {'status': 'Success',
                                        'data': {'total': 0, 'weak': 0}})
    monkeypatch.setattr(r, '_phase_vulns',
                        lambda report, d: {'status': 'Success',
                                           'summary': {'high': 0, 'medium': 0,
                                                       'info': 0, 'risk_score': 0},
                                           'findings': []})

    result = r.run('https://example.com', str(tmp_path))

    project_root = Path(result['project_root'])
    scan_dir = Path(result['project_dir'])
    assert project_root == tmp_path / 'Projects' / 'example.com'
    assert scan_dir.parent == project_root / 'scans'
    # The scan's own report still lives inside the scan dir (layout unchanged).
    assert (scan_dir / 'report.html').exists()
    assert (scan_dir / 'report.json').exists()

    # The scan is indexed in the project metadata + history.
    meta = json.loads((project_root / 'metadata.json').read_text('utf-8'))
    assert meta['scan_count'] == 1
    assert meta['latest_scan']['id'] == result['scan_id']
    assert result['project_scan']['status'] == 'Success'
    assert (project_root / 'history' / f"{result['scan_id']}.json").exists()


def test_render_html_escapes_values():
    r = CollectionRunner()
    report = {
        "url": "https://x/<script>", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "", "phases": {},
    }
    html = r._render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
