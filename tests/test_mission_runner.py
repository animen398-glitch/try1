"""core/mission_runner.py — Mission Center execution (M4), offline/headless."""

import pytest

from core import mission_runner, pentest_mission as pm
from core.audit_store import AuditRunStore
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _ready_mission(project="shop.com", objective="Authorized external review",
                   *, allowed_actions=("headers_check",)):
    mission = pm.create_mission(project, objective,
                                allowed_actions=list(allowed_actions))
    mission = pm.advance_mission_status(mission, "ready")
    return MissionStore().save_mission(mission, now="2026-01-01T09:00:00")


def _seed_finding(project="shop.com"):
    return FindingsStore().upsert(project, Finding(
        category="vuln", rule_id="edge", title="Exposed source map",
        severity="high", location="https://shop.com/app.js.map").to_store(),
        scan_id="s1")["finding"]["id"]


def test_run_mission_completes_and_links_audit_run():
    saved = _ready_mission()
    fid = _seed_finding()

    out = mission_runner.run_mission(saved["payload"], now="2026-01-01T10:00:00")

    assert out["status"] == "completed"
    run_id = out["run_id"]
    # mission persisted as completed + linked to the new audit run
    mission = MissionStore().get_mission(saved["id"])
    assert mission["status"] == "completed"
    assert mission["payload"]["linked_audit_run_ids"] == [run_id]
    # the audit run is a real persisted run carrying the project's finding
    run = AuditRunStore().get_run(run_id)
    assert run["project"] == "shop.com" and run["status"] == "completed"
    assert any(f.get("id") == fid or f.get("finding_id") == fid
               for f in run["payload"].get("findings", []))


def test_run_mission_requires_ready_status():
    mission = pm.create_mission("shop.com", "Draft mission",
                               allowed_actions=["headers_check"])
    saved = MissionStore().save_mission(mission)            # stays 'draft'
    with pytest.raises(ValueError, match="ready"):
        mission_runner.run_mission(saved["payload"])
    assert MissionStore().get_mission(saved["id"])["status"] == "draft"


def test_run_mission_marks_failed_and_reraises_on_orchestration_error(monkeypatch):
    saved = _ready_mission()

    def boom(*_a, **_k):
        raise RuntimeError("orchestration blew up")

    monkeypatch.setattr("core.audit_runner.build_audit_run", boom)
    with pytest.raises(RuntimeError, match="orchestration blew up"):
        mission_runner.run_mission(saved["payload"])

    # mission must not stick in 'running'
    assert MissionStore().get_mission(saved["id"])["status"] == "failed"


def test_run_mission_only_runs_safe_checks_in_allowed_actions():
    # a non-safe-check action is allowed on the mission but contributes no checks
    saved = _ready_mission(allowed_actions=["headers_check"])
    out = mission_runner.run_mission(saved["payload"])
    hunt = next(p for p in out["run"]["phases"] if p["name"] == "finding_hunt")
    actions = {r["action"] for r in hunt["result"].get("safe_checks", [])}
    assert actions == {"headers_check"}
