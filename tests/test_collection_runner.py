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


def test_sync_findings_status_persists_and_decorates(tmp_path):
    from core.project import ProjectStore
    from core.findings_status import fingerprint
    project = ProjectStore(tmp_path).get_or_create("https://x.com")
    report = {"phases": {"vulns": {"status": "Success", "findings": [
        {"title": "Plain HTTP", "severity": "High"},
        {"title": "Weak CSP", "severity": "Medium"}]}}}
    r = CollectionRunner()
    r._sync_findings_status(report, project, "s1")
    # Findings are decorated with status, state is persisted + summarized.
    assert all("status" in f for f in report["phases"]["vulns"]["findings"])
    assert report["findings_status"]["summary"]["total"] == 2
    assert project.load_findings()[fingerprint(
        {"title": "Plain HTTP", "severity": "High"})]["status"] == "open"


def test_render_html_findings_management_card():
    from core.findings_status import apply
    r = CollectionRunner()
    state = apply({}, [{"title": "Plain HTTP", "severity": "High"}], scan_id="s1")
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "", "phases": {},
        "findings_status": {"summary": {"total": 1, "active": 1}, "state": state},
    }
    html = r._render_html(report)
    assert "Findings Management" in html and "Plain HTTP" in html
    assert "<script" not in html.lower()


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
