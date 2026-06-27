import json

import pytest

from core.audit_store import AuditRunStore
from core.audit_workflow import advance_audit_phase, audit_run_to_json, create_audit_run


def _store(tmp_path):
    return AuditRunStore(tmp_path / "audit_runs.db")


def _run(run_id="audit-1", project="shop.com"):
    run = create_audit_run(project, phases=["recon_snapshot"], run_id=run_id)
    return advance_audit_phase(run, "recon_snapshot", {"active_findings": 2})


def test_save_and_load_audit_run_round_trip(tmp_path):
    store = _store(tmp_path)
    run = _run()

    saved = store.save_run(run, now="2026-06-27T10:00:00")
    loaded = store.get_run("audit-1")

    assert saved["id"] == "audit-1"
    assert loaded["project"] == "shop.com"
    assert loaded["status"] == "completed"
    assert loaded["payload"] == audit_run_to_json(run)
    assert loaded["created_at"] == "2026-06-27T10:00:00"


def test_duplicate_save_is_idempotent_and_preserves_created_at(tmp_path):
    store = _store(tmp_path)
    first = _run("audit-dup")
    second = create_audit_run("shop.com", phases=["recon_snapshot"], run_id="audit-dup")

    store.save_run(first, now="2026-06-27T10:00:00")
    store.save_run(second, now="2026-06-27T11:00:00")
    loaded = store.get_run("audit-dup")

    assert loaded["created_at"] == "2026-06-27T10:00:00"
    assert loaded["updated_at"] == "2026-06-27T11:00:00"
    assert loaded["payload"] == audit_run_to_json(second)
    assert len(store.list_runs("shop.com")) == 1


def test_list_runs_filters_project_and_orders_newest_first(tmp_path):
    store = _store(tmp_path)
    store.save_run(_run("old", "shop.com"), now="2026-06-27T10:00:00")
    store.save_run(_run("new", "shop.com"), now="2026-06-27T12:00:00")
    store.save_run(_run("other", "api.com"), now="2026-06-27T13:00:00")

    assert [row["id"] for row in store.list_runs("shop.com")] == ["new", "old"]
    assert [row["id"] for row in store.list_runs()] == ["other", "new", "old"]


def test_save_rejects_malformed_payload(tmp_path):
    store = _store(tmp_path)
    bad = {
        "run_id": "bad",
        "project": "shop.com",
        "profile": "client_safe",
        "status": "completed",
        "phases": "not-a-list",
    }

    with pytest.raises(ValueError):
        store.save_run(bad)


def test_events_are_run_scoped_and_ordered(tmp_path):
    store = _store(tmp_path)
    store.save_run(_run("audit-events"))

    first = store.record_event(
        "audit-events",
        "finding_verified",
        phase="validation",
        finding_id="f1",
        note={"confidence": 90},
        at="2026-06-27T10:00:00",
    )
    second = store.record_event(
        "audit-events",
        "quality_gate_passed",
        phase="risk_business_impact",
        finding_id="f1",
        at="2026-06-27T10:01:00",
    )

    events = store.events("audit-events")
    assert [event["id"] for event in events] == [first["id"], second["id"]]
    assert events[0]["note"] == json.dumps({"confidence": 90}, sort_keys=True)


def test_event_for_unknown_run_raises(tmp_path):
    with pytest.raises(KeyError):
        _store(tmp_path).record_event("missing", "started")


def test_export_run_matches_canonical_payload(tmp_path):
    store = _store(tmp_path)
    run = _run("audit-export")
    store.save_run(run)

    assert store.export_run("audit-export") == audit_run_to_json(run)
    assert json.dumps(store.export_run("audit-export"), sort_keys=True) == json.dumps(
        audit_run_to_json(run),
        sort_keys=True,
    )


def test_delete_run_removes_events(tmp_path):
    store = _store(tmp_path)
    store.save_run(_run("audit-delete"))
    store.record_event("audit-delete", "started")

    assert store.delete_run("audit-delete") is True
    assert store.get_run("audit-delete") is None
    assert store.events("audit-delete") == []
