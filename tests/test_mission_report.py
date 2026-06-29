"""core/mission_report.py — Mission Center report (M5), offline/headless."""

import json

from core import mission_report, mission_runner, pentest_mission as pm
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _ready_mission(project="shop.com", objective="Authorized external review"):
    mission = pm.create_mission(project, objective,
                                allowed_actions=["headers_check"])
    mission = pm.advance_mission_status(mission, "ready")
    return MissionStore().save_mission(mission, now="2026-01-01T09:00:00")


def _seed_finding(project="shop.com", title="Exposed source map"):
    return FindingsStore().upsert(project, Finding(
        category="vuln", rule_id="edge", title=title,
        severity="high", location="https://shop.com/app.js.map").to_store(),
        scan_id="s1")["finding"]["id"]


def test_report_aggregates_linked_run_and_finding():
    saved = _ready_mission()
    fid = _seed_finding()
    # execute → links an audit run carrying the finding
    mission_runner.run_mission(saved["payload"], now="2026-01-01T10:00:00")
    # also explicitly link the finding to the mission
    mission = MissionStore().get_mission(saved["id"])["payload"]
    mission = pm.link_finding(mission, fid)
    MissionStore().save_mission(mission)

    report = mission_report.build_mission_report(
        MissionStore().get_mission(saved["id"])["payload"])

    assert report["summary"]["linked_runs"] == 1
    assert report["summary"]["runs_present"] == 1
    assert report["summary"]["linked_findings"] == 1
    assert len(report["runs"]) == 1 and report["runs"][0]["missing"] is False
    assert report["linked_findings"][0]["id"] == fid


def test_report_marks_stale_links_without_faking():
    mission = pm.create_mission("shop.com", "Stale review",
                               allowed_actions=["headers_check"])
    mission = pm.link_audit_run(mission, "audit-does-not-exist")
    mission = pm.link_finding(mission, "finding-gone")

    report = mission_report.build_mission_report(mission)

    assert report["runs"][0]["missing"] is True
    assert report["linked_findings"][0]["missing"] is True
    assert report["summary"]["runs_present"] == 0


def test_render_json_is_deterministic_and_valid():
    saved = _ready_mission()
    mission_runner.run_mission(saved["payload"])
    report = mission_report.build_mission_report(
        MissionStore().get_mission(saved["id"])["payload"])

    out = mission_report.render_json(report)
    assert json.loads(out)["mission"]["mission_id"] == saved["id"]
    assert out == mission_report.render_json(report)         # deterministic


def test_render_markdown_and_html_sections():
    saved = _ready_mission()
    _seed_finding()
    mission_runner.run_mission(saved["payload"])
    report = mission_report.build_mission_report(
        MissionStore().get_mission(saved["id"])["payload"])

    md = mission_report.render_markdown(report)
    html_doc = mission_report.render_html(report)

    assert md.startswith(f"# Mission Report {saved['id']}")
    assert "## Linked Audit Runs" in md
    assert "## Linked Findings (appendix)" in md
    assert "<html>" in html_doc and "Mission Report" in html_doc
    assert "markdown-sha=" in html_doc
