"""Persistence contract for MissionStore (core/mission_store.py, M2).

Offline/headless: the missions DB is the per-test temp file from conftest's
``_isolate_missions_db`` fixture, so ``MissionStore()`` here and inside the code
point at the same isolated store. Mirrors the AuditRunStore tests: CRUD,
idempotent save, schema-validated export, and the events-less project slice.
"""

import pytest

from core import pentest_mission as pm
from core.mission_store import MissionStore


def _mission(project="acme", objective="obj", **kw):
    return pm.create_mission(project, objective, **kw)


# ── save / get / list / delete ─────────────────────────────────────────────────

def test_save_and_get_round_trip():
    s = MissionStore()
    m = _mission(allowed_actions=["headers_check"])
    saved = s.save_mission(m, now="2026-06-28T10:00:00")
    assert saved["id"] == m["mission_id"]
    assert saved["project"] == "acme" and saved["profile"] == "client_safe"
    got = s.get_mission(m["mission_id"])
    assert got["payload"] == m                       # canonical payload preserved
    assert got["created_at"] == "2026-06-28T10:00:00"


def test_get_unknown_is_none():
    assert MissionStore().get_mission("nope") is None


def test_save_is_idempotent_preserves_created_at():
    s = MissionStore()
    m = _mission()
    s.save_mission(m, now="2026-06-01T00:00:00")
    again = s.save_mission(m, now="2026-06-28T12:00:00")
    assert again["created_at"] == "2026-06-01T00:00:00"   # creation pinned
    assert again["updated_at"] == "2026-06-28T12:00:00"   # moved forward


def test_save_persists_status_change():
    s = MissionStore()
    m = _mission(allowed_actions=["headers_check"])
    s.save_mission(m)
    ready = pm.advance_mission_status(m, "ready")
    s.save_mission(ready)
    assert s.get_mission(m["mission_id"])["status"] == "ready"


def test_list_missions_filters_and_orders():
    s = MissionStore()
    s.save_mission(_mission("p1", "a"), now="2026-06-01T00:00:00")
    s.save_mission(_mission("p1", "b"), now="2026-06-03T00:00:00")
    s.save_mission(_mission("p2", "c"), now="2026-06-02T00:00:00")
    p1 = s.list_missions("p1")
    assert {r["project"] for r in p1} == {"p1"} and len(p1) == 2
    # newest updated_at first
    assert p1[0]["updated_at"] >= p1[1]["updated_at"]
    assert len(s.list_missions()) == 3                 # all projects


def test_delete_mission():
    s = MissionStore()
    m = _mission()
    s.save_mission(m)
    assert s.delete_mission(m["mission_id"]) is True
    assert s.get_mission(m["mission_id"]) is None
    assert s.delete_mission(m["mission_id"]) is False   # already gone


# ── validation on write + export ───────────────────────────────────────────────

def test_save_rejects_invalid_status():
    s = MissionStore()
    m = _mission()
    m["status"] = "weaponized"                          # not in the schema enum
    with pytest.raises(ValueError):
        s.save_mission(m)


def test_export_mission_is_schema_valid():
    from core.audit_schema import validate_audit_payload
    s = MissionStore()
    m = _mission(template="light_client_safe", allowed_actions=["headers_check"])
    s.save_mission(m)
    payload = s.export_mission(m["mission_id"])
    assert validate_audit_payload(payload, "asa_pentest_mission") == payload
    with pytest.raises(KeyError):
        s.export_mission("ghost")


# ── project-scoped export / import (events-less slice) ─────────────────────────

def test_export_project_returns_rows_without_events(tmp_path):
    s = MissionStore(tmp_path / "missions.db")
    s.save_mission(_mission("acme", "a"))
    s.save_mission(_mission("acme", "b"))
    s.save_mission(_mission("other", "c"))
    slice_ = s.export_project("acme")
    assert len(slice_["rows"]) == 2
    assert slice_["events"] == []                       # single-table store


def test_import_project_round_trip(tmp_path):
    src = MissionStore(tmp_path / "src.db")
    m = src.save_mission(_mission("acme", "a"), now="2026-06-10T00:00:00")
    slice_ = src.export_project("acme")

    dst = MissionStore(tmp_path / "dst.db")
    res = dst.import_project("acme", slice_)
    assert res == {"imported": 1, "events": 0, "skipped": False}
    restored = dst.get_mission(m["id"])
    assert restored["payload"] == src.get_mission(m["id"])["payload"]
    assert restored["created_at"] == "2026-06-10T00:00:00"   # verbatim


def test_import_project_skips_existing_unless_replace(tmp_path):
    src = MissionStore(tmp_path / "src.db")
    src.save_mission(_mission("acme", "a"))
    slice_ = src.export_project("acme")

    dst = MissionStore(tmp_path / "dst.db")
    dst.save_mission(_mission("acme", "z"))             # project already populated
    skipped = dst.import_project("acme", slice_)
    assert skipped["skipped"] is True and skipped["imported"] == 0

    replaced = dst.import_project("acme", slice_, replace=True)
    assert replaced["skipped"] is False and replaced["imported"] == 1
    # the original "z" mission is gone, replaced by the imported slice
    assert {r["project"] for r in dst.list_missions("acme")} == {"acme"}
    assert len(dst.list_missions("acme")) == 1
