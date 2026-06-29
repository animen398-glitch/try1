"""core/mission_schedule.py + MissionStore schedule ops — M9, offline/headless."""

from datetime import datetime

import pytest

from core import mission_schedule as ms, pentest_mission as pm
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _ready_mission(project="shop.com", objective="Authorized review"):
    mission = pm.advance_mission_status(
        pm.create_mission(project, objective, allowed_actions=["headers_check"]),
        "ready")
    return MissionStore().save_mission(mission)


def test_store_set_get_schedule_roundtrip():
    saved = _ready_mission()
    store = MissionStore()
    sched = ms.make_mission_schedule("daily", now="2026-01-01T00:00:00")
    store.set_schedule(saved["id"], sched)
    assert store.get_schedule(saved["id"]) == sched
    assert [m["id"] for m in store.list_scheduled()] == [saved["id"]]
    # mission payload/status untouched by scheduling
    assert store.get_mission(saved["id"])["status"] == "ready"


def test_set_schedule_unknown_mission_raises():
    with pytest.raises(KeyError):
        MissionStore().set_schedule("nope", {"enabled": True})


def test_make_schedule_rejects_bad_interval():
    with pytest.raises(ValueError):
        ms.make_mission_schedule("hourly")


def test_run_due_runs_only_enabled_and_due():
    a = _ready_mission("a.io", "one")
    b = _ready_mission("b.io", "two")
    c = _ready_mission("c.io", "three")
    store = MissionStore()
    # a: due (next_run in the past); b: enabled but not due; c: disabled
    ms.set_mission_schedule(a["id"], "daily", store=store,
                            now="2026-01-01T00:00:00")
    store.set_schedule(a["id"], {**store.get_schedule(a["id"]),
                                 "next_run": "2020-01-01T00:00:00"})
    ms.set_mission_schedule(b["id"], "daily", store=store,
                            now="2999-01-01T00:00:00")
    ms.set_mission_schedule(c["id"], "daily", store=store)
    ms.disable_mission_schedule(c["id"], store=store)

    calls = []

    def fake_run(payload, *, now=None):
        calls.append(payload["mission_id"])
        return {"run_id": f"run-{payload['mission_id']}", "status": "completed"}

    out = ms.run_due_missions(store=store, now=datetime(2026, 6, 1), run=fake_run)
    assert [r["mission_id"] for r in out] == [a["id"]]
    assert calls == [a["payload"]["mission_id"]]
    # schedule advanced + last_status recorded
    sched = store.get_schedule(a["id"])
    assert sched["last_status"] == "ok"
    assert sched["next_run"] > "2026-06-01"


def test_run_due_records_failure_without_aborting():
    a = _ready_mission("a.io", "one")
    store = MissionStore()
    ms.set_mission_schedule(a["id"], "daily", store=store)
    store.set_schedule(a["id"], {**store.get_schedule(a["id"]),
                                 "next_run": "2020-01-01T00:00:00"})

    def boom(payload, *, now=None):
        raise RuntimeError("scheduled run failed")

    out = ms.run_due_missions(store=store, run=boom)
    assert out[0]["status"].startswith("error:")
    assert store.get_schedule(a["id"])["last_status"].startswith("error:")


def test_run_mission_audit_links_run_without_status_churn():
    saved = _ready_mission()
    FindingsStore().upsert("shop.com", Finding(
        category="vuln", rule_id="edge", title="Exposed map", severity="high",
        location="https://shop.com/a.js.map").to_store(), scan_id="s1")

    out = ms.run_mission_audit(saved["payload"])
    assert out["status"] == "completed" and out["run_id"]
    mission = MissionStore().get_mission(saved["id"])
    # status stays 'ready' (recurring run does not drive the lifecycle); run linked
    assert mission["status"] == "ready"
    assert out["run_id"] in mission["payload"]["linked_audit_run_ids"]
