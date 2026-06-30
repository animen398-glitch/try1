"""Persistence contract for EngagementStore (core/engagement_store.py, F2).

Offline/headless: the engagements DB is the per-test temp file from conftest's
``_isolate_engagements_db`` fixture, so ``EngagementStore()`` here and inside the
code point at the same isolated store. Mirrors the MissionStore tests: CRUD,
idempotent save, schema-validated export, and the events-less project slice.
"""

import pytest

from core import engagement as eng
from core.engagement_store import EngagementStore


def _engagement(client="Acme", project="shop.io", **kw):
    return eng.create_engagement(client, project, **kw)


# ── save / get / list / delete ─────────────────────────────────────────────────

def test_save_and_get_round_trip():
    s = EngagementStore()
    e = _engagement()
    saved = s.save_engagement(e, now="2026-07-01T10:00:00")
    assert saved["id"] == e["engagement_id"]
    assert saved["client"] == "Acme" and saved["project"] == "shop.io"
    assert saved["profile"] == "client_safe"
    got = s.get_engagement(e["engagement_id"])
    assert got["payload"] == e                        # canonical payload preserved
    assert got["created_at"] == "2026-07-01T10:00:00"


def test_get_unknown_is_none():
    assert EngagementStore().get_engagement("nope") is None


def test_save_is_idempotent_preserves_created_at():
    s = EngagementStore()
    e = _engagement()
    s.save_engagement(e, now="2026-07-01T00:00:00")
    moved = eng.link_finding(e, "f1")
    again = s.save_engagement(moved, now="2026-07-01T12:00:00")
    assert again["created_at"] == "2026-07-01T00:00:00"   # created_at preserved
    assert again["updated_at"] == "2026-07-01T12:00:00"
    assert s.get_engagement(e["engagement_id"])["payload"]["linked_finding_ids"] == ["f1"]


def test_list_by_project_and_all():
    s = EngagementStore()
    s.save_engagement(_engagement("Acme", "a.io"))
    s.save_engagement(_engagement("Beta", "b.io"))
    assert len(s.list_engagements()) == 2
    a = s.list_engagements("a.io")
    assert len(a) == 1 and a[0]["project"] == "a.io"


def test_delete():
    s = EngagementStore()
    e = _engagement()
    s.save_engagement(e)
    assert s.delete_engagement(e["engagement_id"]) is True
    assert s.get_engagement(e["engagement_id"]) is None
    assert s.delete_engagement(e["engagement_id"]) is False


# ── export / schema ──────────────────────────────────────────────────────────--

def test_export_is_schema_valid_payload():
    s = EngagementStore()
    e = _engagement(scope={"allowed_domains": ["shop.io"]})
    s.save_engagement(e)
    exported = s.export_engagement(e["engagement_id"])
    assert exported == e                              # canonical, schema-valid
    assert exported["profile"] == "client_safe"


def test_export_unknown_raises():
    with pytest.raises(KeyError):
        EngagementStore().export_engagement("nope")


def test_save_requires_client_and_project():
    s = EngagementStore()
    with pytest.raises(ValueError):
        s.save_engagement(eng.normalize_engagement({"project": "shop.io"}))  # no client
    with pytest.raises(ValueError):
        s.save_engagement(eng.normalize_engagement({"client": "Acme"}))      # no project


# ── events-less project slice (project_io contract) ─────────────────────────────

def test_project_export_slice_is_events_less():
    s = EngagementStore()
    s.save_engagement(_engagement("Acme", "shop.io"))
    slice_ = s.export_project("shop.io")
    assert [r["project"] for r in slice_["rows"]] == ["shop.io"]
    assert slice_["events"] == []                     # single-table, no event log


def test_project_import_round_trip(tmp_path):
    src = EngagementStore(tmp_path / "src.db")
    e = _engagement("Acme", "shop.io")
    src.save_engagement(e)
    payload = src.export_project("shop.io")

    dst = EngagementStore(tmp_path / "dst.db")
    dst.validate_project_import("shop.io", payload)
    out = dst.import_project("shop.io", payload, replace=True)
    assert out["imported"] == 1
    assert dst.get_engagement(e["engagement_id"])["payload"] == e
