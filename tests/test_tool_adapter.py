"""core/tool_adapter.py — Mission Center M3 tool adapter contract (offline).

Pure/offline contract: builds tool requests, gates them against the mission's
ROE via the existing scope/action policy, and normalizes parsed output into
store-free DTOs. Nothing here runs a tool, opens a socket, or writes to a store.
"""

import json

import pytest

from core import pentest_mission as pm
from core.audit_schema import validate_audit_payload
from core.tool_adapter import (
    ToolAsset,
    ToolCapability,
    ToolFinding,
    ToolRunRequest,
    ToolRunResult,
    build_tool_request,
    evaluate_tool_allowed_for_mission,
    map_tool_result_to_findings,
    normalize_tool_name,
    tool_result_to_json,
)


def _active_mission():
    """A mission whose ROE authorizes active checks against example.com."""
    return pm.create_mission(
        "Example",
        "External review",
        roe={
            "allowed_domains": ["example.com"],
            "active_scan_enabled": True,
            "passive_only": False,
            "authorized_by": "client",
            "rate_limit": "60/min",
        },
        allowed_actions=["headers_check", "safe_active_probe"],
    )


def _passive_mission():
    """Default ROE: passive_only, no active checks."""
    return pm.create_mission("Example", "Passive review",
                             allowed_actions=["safe_active_probe"])


def test_build_tool_request_is_canonical_and_deterministic():
    mission = _active_mission()

    first = build_tool_request(mission, "Header_Audit", params={"b": 2, "a": 1})
    second = build_tool_request(mission, "header_audit", params={"a": 1, "b": 2})

    assert first == second
    assert isinstance(first, ToolRunRequest)
    payload = first.to_dict()
    assert list(payload["params"].keys()) == ["a", "b"]
    assert json.dumps(payload, sort_keys=True) == json.dumps(
        second.to_dict(), sort_keys=True
    )


def test_normalize_and_unknown_tool_rejected():
    assert normalize_tool_name("  TLS_Audit ") == "tls_audit"

    with pytest.raises(ValueError, match="tool name is required"):
        normalize_tool_name("")
    with pytest.raises(ValueError, match="unknown tool"):
        build_tool_request(_active_mission(), "metasploit")


def test_tool_request_references_mission_identity_target_profile_scope():
    mission = _active_mission()

    request = build_tool_request(mission, "header_audit")

    assert request.mission_id == mission["mission_id"]
    assert request.project == mission["project"]
    assert request.target == "https://example.com"      # derived from ROE
    assert request.profile == mission["profile"]
    assert request.roe == mission["roe"]                 # ROE is the scope SSOT
    assert request.action == "headers_check"


def test_evaluate_reuses_action_and_scope_policy_for_forbidden_action():
    mission = _active_mission()
    # A capability mapped onto a forbidden action class must be blocked by the
    # existing action policy, not by anything re-implemented here.
    forbidden = ToolCapability("rogue", "credential_bruteforce", passive=False)

    decision = evaluate_tool_allowed_for_mission(mission, forbidden)

    assert decision["allowed"] is False
    assert "forbidden" in decision["reason"]
    assert decision["tool"] == "rogue"


def test_passive_default_blocks_active_checks():
    mission = _passive_mission()

    decision = evaluate_tool_allowed_for_mission(
        mission, "safe_active_prober", target="https://example.com")

    assert decision["allowed"] is False
    assert decision["reason"] == "project is passive_only"


def test_active_in_scope_safe_action_allowed_when_scope_enables_it():
    mission = _active_mission()

    allowed = evaluate_tool_allowed_for_mission(mission, "safe_active_prober")
    outside = evaluate_tool_allowed_for_mission(
        mission, "safe_active_prober", target="https://outside.test"
    )

    assert allowed["allowed"] is True
    assert outside["allowed"] is False
    assert outside["reason"] == "host outside.test is outside allowed domains"


def test_result_export_validates_against_schema_and_is_deterministic():
    mission = _active_mission()
    request = build_tool_request(mission, "header_audit")
    parser_output = {
        "findings": [
            {
                "title": "Missing CSP",
                "severity": "MEDIUM",
                "asset": "example.com",
                "location": "https://example.com/app",
                "evidence_refs": ["artifact:2", "artifact:1"],
            }
        ],
        "assets": [{"value": "example.com", "type": "domain", "source": "header_audit"}],
        "evidence_refs": ["artifact:1", "artifact:1"],
    }

    result = map_tool_result_to_findings(request, parser_output)
    first = tool_result_to_json(result)
    second = tool_result_to_json(result)

    validate_audit_payload(first, "asa_tool_run")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["findings"][0]["severity"] == "medium"
    assert first["findings"][0]["evidence_refs"] == ["artifact:1", "artifact:2"]
    assert first["evidence_refs"] == ["artifact:1"]


def test_parser_output_maps_to_normalized_dtos_without_writing_stores():
    mission = _active_mission()
    request = build_tool_request(mission, "header_audit")
    parser_output = {
        "findings": [
            {"title": "B finding", "severity": "low", "asset": "a", "location": "/b"},
            {"title": "A finding", "severity": "weird", "asset": "a", "location": "/a"},
        ],
        "assets": [
            {"value": "example.com", "asset_type": "domain", "source": "t"},
            {"value": "example.com", "asset_type": "domain", "source": "t"},
        ],
    }

    result = map_tool_result_to_findings(request, parser_output)

    assert isinstance(result, ToolRunResult)
    assert all(isinstance(f, ToolFinding) for f in result.findings)
    assert all(isinstance(a, ToolAsset) for a in result.assets)
    # Unknown severity normalized to info; assets deduped.
    assert {f.severity for f in result.findings} == {"low", "info"}
    assert len(result.assets) == 1
    # Deterministic ordering by (severity, title, ...).
    assert [f.severity for f in result.findings] == ["info", "low"]


def test_invalid_result_status_rejected():
    mission = _active_mission()
    request = build_tool_request(mission, "header_audit")

    with pytest.raises(ValueError, match="invalid tool run status"):
        map_tool_result_to_findings(request, {}, status="exploited")
