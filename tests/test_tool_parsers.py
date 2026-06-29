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


def test_dispatch_rejects_empty_and_unknown_and_unparsed_tools():
    with pytest.raises(ValueError, match="tool name is required"):
        tp.parse_tool_output("", {})
    with pytest.raises(ValueError, match="no parser for tool"):
        tp.parse_tool_output("metasploit", {})
    # a registered M3 tool with no parser yet is also rejected
    with pytest.raises(ValueError, match="no parser for tool"):
        tp.parse_tool_output("tls_audit", {})
    assert tp.has_parser("Header_Audit") is True
    assert tp.has_parser("tls_audit") is False
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
