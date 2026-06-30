"""core/tool_report.py — pure offline tool-run report renderers.

JSON / MD / HTML over a ToolRunResult's canonical payload. A view, not storage:
deterministic, offline, no store writes.
"""

import json

import pytest

from core import pentest_mission as pm, tool_report as tr
from core.tool_adapter import ToolRunResult, tool_result_to_json
from core.tool_pipeline import assemble_tool_run


def _result():
    mission = pm.create_mission(
        "Example", "External review",
        roe={"allowed_domains": ["example.com"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check", "safe_active_probe"])
    # one finding (missing HSTS) + one asset (the domain)
    return assemble_tool_run(
        mission, "header_audit", {"url": "https://example.com/app", "headers": {}})


def _empty_result():
    return ToolRunResult(tool="header_audit", action="headers_check",
                         mission_id="m1", target="https://example.com",
                         status="completed")


def test_render_json_matches_canonical_payload_and_is_deterministic():
    result = _result()
    out = tr.render_json(result)
    assert json.loads(out) == tool_result_to_json(result)
    assert out == tr.render_json(result)                 # deterministic


def test_render_markdown_has_header_and_tables():
    md = tr.render_markdown(_result())
    assert md.startswith("# Tool Run header_audit")
    assert "- Status: completed" in md
    assert "## Findings" in md and "## Assets" in md
    assert "Missing Strict-Transport-Security header" in md
    assert "| Type | Value | Source |" in md


def test_render_markdown_empty_result():
    md = tr.render_markdown(_empty_result())
    assert "No findings." in md and "No assets." in md


def test_render_html_is_escaped_and_carries_markdown_sha():
    htmldoc = tr.render_html(_result())
    assert "<html>" in htmldoc and "Tool Run header_audit" in htmldoc
    assert "markdown-sha=" in htmldoc
    assert "<h2>Findings</h2>" in htmldoc and "<h2>Assets</h2>" in htmldoc


def test_renderers_reject_non_result():
    for renderer in (tr.render_json, tr.render_markdown, tr.render_html):
        with pytest.raises(TypeError):
            renderer({"not": "a result"})
