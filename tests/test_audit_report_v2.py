"""Contract tests for Workbench v2 F5 — template/compare report surfaces."""

import json

from core.audit_compare import compare_runs
from core.audit_report import (
    render_compare_html,
    render_compare_json,
    render_compare_markdown,
    render_html,
    render_markdown,
)
from core.audit_workflow import create_audit_run


def _run(run_id, findings, **kw):
    return {
        "run_id": run_id,
        "project": "example.com",
        "profile": "client_safe",
        "status": "completed",
        "phases": [{"name": "validation", "status": "completed", "result": None}],
        "findings": findings,
        "events": [],
        **kw,
    }


def _f(fid, severity, validation="verified"):
    return {"finding_id": fid, "severity": severity, "validation_status": validation,
            "title": f"Issue {fid}"}


def test_run_report_shows_scenario_context():
    run = create_audit_run("example.com", template="authenticated_review",
                           run_id="audit-f5-ctx")
    md = render_markdown(run)
    assert "Scenario: authenticated_review" in md
    assert "Authenticated context: yes" in md
    assert "ROE:" in md
    html_out = render_html(run)
    assert "authenticated_review" in html_out


def test_bare_run_report_has_no_scenario_block():
    run = create_audit_run("example.com", run_id="audit-f5-bare")
    md = render_markdown(run)
    assert "Scenario:" not in md
    assert "Authenticated context:" not in md


def test_compare_renderers_are_deterministic_and_valid():
    diff = compare_runs(
        _run("b", [_f("x", "low"), _f("gone", "high")]),
        _run("c", [_f("x", "high"), _f("fresh", "critical")]),
    )
    md = render_compare_markdown(diff)
    assert "# Audit Compare c vs b" in md
    assert "Gate: FAIL" in md
    assert "## Regressed" in md and "## New" in md and "## Resolved" in md

    html_out = render_compare_html(diff)
    assert "Audit Compare" in html_out
    assert "Gate:</b> FAIL" in html_out

    # JSON surface round-trips and validates against the compare schema
    parsed = json.loads(render_compare_json(diff))
    assert parsed["summary"]["regressed"] == 1
    assert parsed["candidate_run_id"] == "c"
    # deterministic
    assert render_compare_markdown(diff) == md


def test_compare_inconclusive_note_surfaces():
    base = _run("b", [_f("x", "high")])
    cand = _run("c", [])
    cand["phases"] = [{"name": "validation", "status": "failed", "result": None}]
    cand["status"] = "failed"
    diff = compare_runs(base, cand)
    md = render_compare_markdown(diff)
    assert "Inconclusive: yes" in md
    assert "Gate: PASS" in md  # failed phase alone does not fail the gate
