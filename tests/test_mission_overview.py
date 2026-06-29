"""core/mission_overview.py — Mission Center portfolio overview (M7), offline."""

from core import mission_overview, mission_runner, pentest_mission as pm
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _mission(project, objective, *, status="draft"):
    m = pm.create_mission(project, objective, allowed_actions=["headers_check"])
    if status != "draft":
        m = pm.advance_mission_status(m, status)
    return MissionStore().save_mission(m)


def test_overview_counts_by_status():
    _mission("a.io", "one", status="draft")
    _mission("b.io", "two", status="ready")
    _mission("c.io", "three", status="ready")

    out = mission_overview.build_mission_overview()
    assert out["total"] == 3
    assert out["counts"]["ready"] == 2
    assert out["counts"]["draft"] == 1
    assert out["counts"]["completed"] == 0


def test_overview_reports_last_run_outcome():
    saved = _mission("shop.com", "review", status="ready")
    FindingsStore().upsert("shop.com", Finding(
        category="vuln", rule_id="edge", title="Exposed map", severity="high",
        location="https://shop.com/a.js.map").to_store(), scan_id="s1")
    mission_runner.run_mission(saved["payload"])

    out = mission_overview.build_mission_overview()
    row = next(r for r in out["missions"] if r["mission_id"] == saved["id"])
    assert row["status"] == "completed"
    assert row["last_run_id"]
    assert row["last_run_status"] == "completed"


def test_overview_scoped_to_project():
    _mission("a.io", "one", status="ready")
    _mission("b.io", "two", status="ready")
    out = mission_overview.build_mission_overview(project="a.io")
    assert out["total"] == 1
    assert {r["project"] for r in out["missions"]} == {"a.io"}


def test_overview_empty_is_well_formed():
    out = mission_overview.build_mission_overview()
    assert out == {"total": 0,
                   "counts": {s: 0 for s in out["counts"]},
                   "client_facing": 0, "missions": []}
    assert out["counts"]["draft"] == 0
