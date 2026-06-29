"""core/tool_pipeline.py — offline tool-evidence pipeline (gate → parse → map).

Composes evaluate_tool_allowed_for_mission + parse_tool_output +
map_tool_result_to_findings into one store-free ToolRunResult. Nothing here runs
a tool, opens a socket, or writes to a store.
"""

import json

from core import pentest_mission as pm
from core.tool_adapter import ToolRunResult
from core.tool_pipeline import assemble_tool_run


def _active_mission():
    return pm.create_mission(
        "Example", "External review",
        roe={"allowed_domains": ["example.com"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check", "safe_active_probe"])


def _passive_mission():
    return pm.create_mission(
        "Example", "Passive review",
        roe={"allowed_domains": ["example.com"], "active_scan_enabled": False,
             "passive_only": True},
        allowed_actions=["headers_check"])


def test_allowed_tool_parses_and_maps_to_completed_result():
    mission = _active_mission()

    result = assemble_tool_run(
        mission, "header_audit",
        {"url": "https://example.com/app", "headers": {}})

    assert isinstance(result, ToolRunResult)
    assert result.status == "completed"
    assert result.tool == "header_audit"
    assert any(f.title == "Missing Strict-Transport-Security header"
               for f in result.findings)
    assert any(a.asset_type == "domain" for a in result.assets)


def test_blocked_tool_yields_blocked_result_without_parsing():
    mission = _passive_mission()

    result = assemble_tool_run(
        mission, "safe_active_prober",
        {"urls": ["https://example.com/api"]}, target="https://example.com")

    assert result.status == "blocked"
    assert result.findings == [] and result.assets == []


def test_allowed_but_no_parser_yields_skipped():
    mission = _active_mission()
    # tls_audit is a registered M3 tool but has no parser yet.
    result = assemble_tool_run(mission, "tls_audit", {}, target="https://example.com")
    assert result.status == "skipped"
    assert result.findings == [] and result.assets == []


def test_asset_parser_through_pipeline():
    mission = _active_mission()

    result = assemble_tool_run(
        mission, "safe_active_prober",
        {"urls": ["https://example.com/api"], "hosts": ["api.example.com"]})

    assert result.status == "completed"
    assert result.findings == []
    assert {a.asset_type for a in result.assets} == {"url", "subdomain"}


def test_pipeline_is_deterministic():
    mission = _active_mission()
    evidence = {"url": "https://example.com/app", "headers": {}}
    first = assemble_tool_run(mission, "header_audit", evidence).to_dict()
    second = assemble_tool_run(mission, "header_audit", evidence).to_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
