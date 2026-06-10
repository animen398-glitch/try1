"""Tests for CollectionRunner pure helpers (no pipeline / network)."""

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


def test_render_html_escapes_values():
    r = CollectionRunner()
    report = {
        "url": "https://x/<script>", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "", "phases": {},
    }
    html = r._render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
