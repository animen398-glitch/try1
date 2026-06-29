"""core/tool_parsers.py — per-tool offline parsers (offline/deterministic).

Parsers turn already-captured evidence into the generic {findings, assets} shape
that core.tool_adapter.map_tool_result_to_findings consumes. Nothing here runs a
tool, opens a socket, or writes to a store; detection logic is reused from
core.audit_checks.
"""

import json

import pytest

from core import pentest_mission as pm, tool_parsers as tp
from core.tool_adapter import (
    ToolRunResult,
    build_tool_request,
    map_tool_result_to_findings,
)


def _mission():
    return pm.create_mission(
        "Example", "External review",
        roe={"allowed_domains": ["example.com"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check"])


def test_header_audit_reuses_audit_checks_detection():
    out = tp.parse_tool_output(
        "header_audit", {"url": "https://example.com/app", "headers": {}})
    titles = [f["title"] for f in out["findings"]]
    assert "Missing Strict-Transport-Security header" in titles
    f = out["findings"][0]
    assert f["severity"] == "medium"
    assert f["asset"] == "example.com"
    assert f["evidence_refs"] == ["headers:https://example.com/app"]
    # the target host is emitted as a domain asset
    assert {"value": "example.com", "asset_type": "domain",
            "source": "header_audit"} in out["assets"]


def test_cookie_audit_flags_missing_secure_httponly():
    out = tp.parse_tool_output(
        "cookie_audit",
        {"url": "https://example.com", "cookies": [{"name": "sid"}]})
    assert out["findings"][0]["title"] == "Cookie sid missing Secure/HttpOnly"
    assert out["findings"][0]["severity"] == "medium"


def test_source_map_finder_detects_map_urls():
    out = tp.parse_tool_output(
        "source_map_finder",
        {"urls": ["https://example.com/app.js.map", "https://example.com/x.js"]})
    assert len(out["findings"]) == 1
    assert out["findings"][0]["location"] == "https://example.com/app.js.map"


def test_safe_active_prober_emits_assets_no_findings():
    out = tp.parse_tool_output(
        "safe_active_prober",
        {"urls": ["https://example.com/api", "https://example.com/api"],
         "hosts": ["api.example.com"], "subdomains": ["cdn.example.com"]})
    assert out["findings"] == []
    assets = {(a["asset_type"], a["value"]) for a in out["assets"]}
    assert ("url", "https://example.com/api") in assets        # deduped
    assert ("subdomain", "api.example.com") in assets
    assert ("subdomain", "cdn.example.com") in assets
    assert len(out["assets"]) == 3


def test_dispatch_rejects_empty_and_unknown_tools():
    with pytest.raises(ValueError, match="tool name is required"):
        tp.parse_tool_output("", {})
    # a tool with no registered parser (not in PARSERS) is rejected
    with pytest.raises(ValueError, match="no parser for tool"):
        tp.parse_tool_output("metasploit", {})
    assert tp.has_parser("Header_Audit") is True
    assert tp.has_parser("nessus") is False        # no parser registered
    assert tp.has_parser("") is False


def test_parser_output_feeds_map_tool_result_to_findings():
    mission = _mission()
    request = build_tool_request(mission, "header_audit")
    parsed = tp.parse_tool_output(
        "header_audit", {"url": "https://example.com/app", "headers": {}})

    result = map_tool_result_to_findings(request, parsed)

    assert isinstance(result, ToolRunResult)
    assert result.tool == "header_audit"
    assert any(f.title == "Missing Strict-Transport-Security header"
               for f in result.findings)
    assert any(a.asset_type == "domain" for a in result.assets)


def test_parse_tool_output_is_deterministic():
    evidence = {"url": "https://example.com/app", "headers": {}}
    first = tp.parse_tool_output("header_audit", evidence)
    second = tp.parse_tool_output("header_audit", evidence)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ── remaining registry-tool parsers ──────────────────────────────────────────

def test_all_registry_tools_have_parsers():
    from core.tool_adapter import TOOL_CAPABILITIES
    assert all(tp.has_parser(name) for name in TOOL_CAPABILITIES)


def test_dependency_auditor_reuses_dependency_audit():
    out = tp.parse_tool_output(
        "dependency_auditor",
        {"url": "https://example.com",
         "scripts": ["https://cdn.example.com/jquery-1.7.1.min.js"], "html": ""})
    assert any("jQuery" in f["title"] for f in out["findings"])
    assert {"value": "example.com", "asset_type": "domain",
            "source": "dependency_auditor"} in out["assets"]


def test_graphql_introspector_flags_open_introspection_only():
    on = tp.parse_tool_output(
        "graphql_introspector",
        {"url": "https://example.com/graphql",
         "introspection": {"data": {"__schema": {"types": []}}}})
    assert [f["title"] for f in on["findings"]] == ["GraphQL introspection enabled"]
    assert on["findings"][0]["severity"] == "medium"

    off = tp.parse_tool_output(
        "graphql_introspector",
        {"url": "https://example.com/graphql", "introspection": {"errors": [{}]}})
    assert off["findings"] == []


def test_tls_audit_flags_deprecated_protocols_and_weak_ciphers():
    out = tp.parse_tool_output(
        "tls_audit",
        {"url": "https://example.com",
         "protocols": ["TLSv1.0", "TLSv1.3"],
         "ciphers": ["TLS_RSA_WITH_RC4_128_SHA", "TLS_AES_256_GCM_SHA384"]})
    titles = [f["title"] for f in out["findings"]]
    assert "Deprecated TLS protocol enabled: TLSv1.0" in titles
    assert any("Weak TLS cipher" in t for t in titles)
    # the modern protocol/cipher are not flagged
    assert not any("TLSv1.3" in t or "AES_256" in t for t in titles)


def test_iac_config_auditor_reuses_scan_path(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n",
                                         encoding="utf-8")
    out = tp.parse_tool_output("iac_config_auditor", {"path": str(tmp_path)})
    titles = [f["title"] for f in out["findings"]]
    assert any("root" in t.lower() for t in titles)
    assert {"value": "python:latest", "asset_type": "container_image",
            "source": "iac_config_auditor"} in out["assets"]


def test_iac_config_auditor_empty_path_is_safe():
    assert tp.parse_tool_output("iac_config_auditor", {}) == {"findings": [],
                                                              "assets": []}
