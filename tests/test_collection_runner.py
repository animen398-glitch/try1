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
