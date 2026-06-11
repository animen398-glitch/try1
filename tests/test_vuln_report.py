"""Tests for the standalone vulnerability report (HTML + JSON export)."""

import json

from core.vuln_report import export, render_html


_FINDINGS = [
    {"severity": "High", "title": "Plain HTTP", "detail": "unencrypted"},
    {"severity": "Medium", "title": "Weak CSP", "detail": "unsafe-inline"},
    {"severity": "Info", "title": "CMS fingerprinted"},
]


def test_render_html_groups_by_severity():
    out = render_html("https://example.com", _FINDINGS)
    assert out.startswith("<!DOCTYPE html>")
    assert "Vulnerability Report" in out
    assert "https://example.com" in out
    assert "High (1)" in out and "Medium (1)" in out and "Info (1)" in out
    assert "Plain HTTP" in out and "Weak CSP" in out
    assert "risk score:" in out


def test_render_html_escapes():
    out = render_html("https://x/<script>", [
        {"severity": "High", "title": "<b>xss</b>", "detail": "<i>d</i>"},
    ])
    assert "<script>" not in out
    assert "&lt;b&gt;xss&lt;/b&gt;" in out


def test_render_html_no_findings():
    out = render_html("https://x", [])
    assert "No findings" in out


def test_export_writes_both_files(tmp_path):
    paths = export(str(tmp_path / "report"), "https://example.com", _FINDINGS)
    assert paths["html"].endswith(".html") and paths["json"].endswith(".json")
    html_text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Vulnerability Report" in html_text
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["target"] == "https://example.com"
    assert data["summary"]["high"] == 1
    assert len(data["findings"]) == 3


def test_export_strips_given_extension(tmp_path):
    # Passing a .html path should still produce both .html and .json.
    export(str(tmp_path / "r.html"), "t", _FINDINGS)
    assert (tmp_path / "r.html").exists()
    assert (tmp_path / "r.json").exists()


def test_pdf_safe_transliterates_unicode():
    from core.vuln_report import _pdf_safe
    assert _pdf_safe("a — b → c ≈ d") == "a - b -> c ~ d"
    # Cyrillic falls back to latin-1 replacement (no crash).
    assert isinstance(_pdf_safe("куки"), str)


def test_export_pdf_when_available(tmp_path):
    import pytest
    pytest.importorskip("fpdf")
    from core.vuln_report import export_pdf
    out = export_pdf(tmp_path / "r.pdf", "https://example.com", _FINDINGS)
    assert out is not None
    data = (tmp_path / "r.pdf").read_bytes()
    assert data[:4] == b"%PDF"


def test_export_includes_pdf_when_available(tmp_path):
    import importlib.util
    paths = export(str(tmp_path / "report"), "https://example.com", _FINDINGS)
    if importlib.util.find_spec("fpdf"):
        assert "pdf" in paths and (tmp_path / "report.pdf").exists()
    else:
        assert "pdf" not in paths
