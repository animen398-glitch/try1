"""core/engagement_report.py — Engagement report (F4), offline/headless.

Evidence-first deliverable aggregating an engagement's linked missions, audit
runs (reusing core.audit_report) and findings, plus pure JSON/MD/HTML renderers.
"""

import json

from core import engagement as eng
from core import engagement_report, mission_runner, pentest_mission as pm
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _ready_mission(project="shop.com", objective="External review"):
    mission = pm.advance_mission_status(
        pm.create_mission(project, objective, allowed_actions=["headers_check"]),
        "ready")
    return MissionStore().save_mission(mission, now="2026-01-01T09:00:00")


def _seed_finding(project="shop.com"):
    return FindingsStore().upsert(project, Finding(
        category="vuln", rule_id="edge", title="Exposed source map",
        severity="high", location="https://shop.com/app.js.map").to_store(),
        scan_id="s1")["finding"]["id"]


def test_report_aggregates_missions_runs_findings():
    saved = _ready_mission()
    fid = _seed_finding()
    run_id = mission_runner.run_mission(saved["payload"],
                                        now="2026-01-01T10:00:00")["run_id"]

    e = eng.create_engagement("Acme Corp", "shop.com",
                              authorization={"accepted": True})
    e = eng.link_mission(e, saved["id"])
    e = eng.link_audit_run(e, run_id)
    e = eng.link_finding(e, fid)

    report = engagement_report.build_engagement_report(e)
    s = report["summary"]
    assert s["linked_missions"] == 1 and s["missions_present"] == 1
    assert s["linked_runs"] == 1 and s["runs_present"] == 1
    assert s["linked_findings"] == 1
    assert report["missions"][0]["objective"] == "External review"
    assert report["runs"][0]["missing"] is False
    assert report["linked_findings"][0]["id"] == fid


def test_report_marks_stale_links_without_faking():
    e = eng.create_engagement("Acme", "shop.com")
    e = eng.link_mission(e, "mission-gone")
    e = eng.link_audit_run(e, "audit-gone")
    e = eng.link_finding(e, "finding-gone")

    report = engagement_report.build_engagement_report(e)
    assert report["missions"][0]["missing"] is True
    assert report["runs"][0]["missing"] is True
    assert report["linked_findings"][0]["missing"] is True
    assert report["summary"]["missions_present"] == 0
    assert report["summary"]["runs_present"] == 0


def test_renderers_are_pure_and_shaped():
    e = eng.create_engagement("Acme Corp", "shop.com",
                              scope={"allowed_domains": ["shop.com"]},
                              authorization={"accepted": True,
                                             "authorized_by": "CISO"})
    report = engagement_report.build_engagement_report(e)

    md = engagement_report.render_markdown(report)
    assert md.startswith("# Engagement Report ")
    assert "Acme Corp" in md and "Client-facing findings:" in md

    htmldoc = engagement_report.render_html(report)
    assert "<html>" in htmldoc and "markdown-sha=" in htmldoc
    assert "Engagement Report" in htmldoc

    parsed = json.loads(engagement_report.render_json(report))
    assert parsed["engagement"]["client"] == "Acme Corp"
    # deterministic: same input → identical render
    assert engagement_report.render_markdown(report) == md


def test_empty_engagement_renders_cleanly():
    e = eng.create_engagement("Acme", "shop.com")
    report = engagement_report.build_engagement_report(e)
    md = engagement_report.render_markdown(report)
    assert "No missions linked to this engagement." in md
    assert "No audit runs linked to this engagement." in md
