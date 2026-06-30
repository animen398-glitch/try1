"""core/tool_ingest.py — bridge ToolRunResult → canonical Finding/Asset DTOs.

Pure converter: maps the tool layer's result onto the platform's identity-bearing
Finding / Asset DTOs (reusing findings_adapter / asset_adapter). Writes to no
store, performs no I/O.
"""

import pytest

from core import pentest_mission as pm, tool_ingest as ti
from core.asset_adapter import Asset
from core.findings_adapter import Finding
from core.tool_adapter import ToolRunResult
from core.tool_pipeline import assemble_tool_run


def _mission():
    return pm.create_mission(
        "Example", "External review",
        roe={"allowed_domains": ["example.com"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check", "safe_active_probe"])


def _header_result():
    return assemble_tool_run(
        _mission(), "header_audit", {"url": "https://example.com/app", "headers": {}})


def test_findings_get_canonical_identity_and_category():
    findings = ti.tool_result_to_findings(_header_result())

    assert findings and all(isinstance(f, Finding) for f in findings)
    f = findings[0]
    assert f.category == "header"                    # mapped from the action
    assert f.rule_id and f.title.startswith("Missing")
    assert f.severity == "medium"
    assert f.source == "header_audit"
    assert f.id                                      # fingerprint identity present
    # the tool's string refs are preserved in detail (not manifest artifacts)
    stored = f.to_store()
    assert stored["category"] == "header"
    assert "headers:" in stored["evidence"]["detail"]


def test_dependency_finding_category_is_vuln():
    result = assemble_tool_run(
        _mission(), "dependency_auditor",
        {"url": "https://example.com",
         "scripts": ["https://cdn.example.com/jquery-1.7.1.min.js"]})
    findings = ti.tool_result_to_findings(result)
    assert findings and all(f.category == "vuln" for f in findings)


def test_assets_map_onto_asset_dtos_with_source():
    result = assemble_tool_run(
        _mission(), "safe_active_prober",
        {"urls": ["https://example.com/api"], "hosts": ["api.example.com"]})
    assets = ti.tool_result_to_assets(result)

    assert all(isinstance(a, Asset) for a in assets)
    by_type = {a.type: a for a in assets}
    assert by_type["url"].value == "https://example.com/api"
    assert by_type["subdomain"].value == "api.example.com"
    assert by_type["url"].attrs["source"] == "safe_active_prober"


def test_blocked_result_yields_no_findings_or_assets():
    passive = pm.create_mission(
        "Example", "Passive",
        roe={"allowed_domains": ["example.com"], "active_scan_enabled": False,
             "passive_only": True},
        allowed_actions=["headers_check"])
    result = assemble_tool_run(
        passive, "header_audit", {"url": "https://example.com", "headers": {}})
    assert result.status == "blocked"
    assert ti.tool_result_to_findings(result) == []
    assert ti.tool_result_to_assets(result) == []


def test_bridge_is_deterministic_and_pure():
    result = _header_result()
    first = [f.to_store() for f in ti.tool_result_to_findings(result)]
    second = [f.to_store() for f in ti.tool_result_to_findings(result)]
    assert first == second                           # deterministic
    # stable finding identity across calls (pure, no state)
    ids_a = {f.id for f in ti.tool_result_to_findings(result)}
    ids_b = {f.id for f in ti.tool_result_to_findings(result)}
    assert ids_a == ids_b and ids_a


def test_rejects_non_result():
    with pytest.raises(TypeError):
        ti.tool_result_to_findings({"not": "a result"})
    with pytest.raises(TypeError):
        ti.tool_result_to_assets({"not": "a result"})


def test_empty_result_maps_to_empty_lists():
    empty = ToolRunResult(tool="header_audit", action="headers_check",
                          mission_id="m1", target="https://example.com",
                          status="completed")
    assert ti.tool_result_to_findings(empty) == []
    assert ti.tool_result_to_assets(empty) == []
