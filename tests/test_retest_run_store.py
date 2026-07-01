"""core/retest_run_store.py — RetestRunStore persistence (R2).

Single-table, events-less SQLite store for retest-run snapshots. Mirrors
test_mission_store.py / test_engagement_store.py. Offline, per-test isolated DB
via the conftest ``_isolate_retest_runs_db`` fixture.
"""

import pytest

from core import engagement as eng
from core import retest_run as rr
from core.retest_run_store import RetestRunStore


def _run(created_at="2026-07-01T10:00:00Z", project="shop.io",
         client="Acme Corp", finding_results=None, status="completed"):
    e = eng.create_engagement(client, project)
    run = rr.create_retest_run(e, created_at=created_at,
                               finding_results=finding_results or [])
    if status != "pending":
        run = rr.advance_retest_run_status(run, status)
    return run


def test_save_and_get_roundtrip():
    store = RetestRunStore()
    saved = store.save_retest_run(_run())
    assert saved["id"].startswith("rt-")
    assert saved["status"] == "completed"
    got = store.get_retest_run(saved["id"])
    assert got is not None
    # payload is JSON-decoded on read
    assert isinstance(got["payload"], dict)
    assert got["payload"]["engagement_id"] == saved["engagement_id"]


def test_created_at_mirrors_snapshot_time():
    store = RetestRunStore()
    saved = store.save_retest_run(_run(created_at="2026-07-01T10:00:00Z"))
    assert saved["created_at"] == "2026-07-01T10:00:00Z"


def test_save_is_idempotent_preserves_created_at():
    store = RetestRunStore()
    run = _run()
    first = store.save_retest_run(run, now="2026-07-01T11:00:00Z")
    # re-save the same run id later — created_at stays, updated_at moves
    again = store.save_retest_run(run, now="2026-07-02T11:00:00Z")
    assert first["id"] == again["id"]
    assert again["created_at"] == first["created_at"]
    assert again["updated_at"] == "2026-07-02T11:00:00Z"
    assert len(store.list_retest_runs()) == 1


def test_save_validates_payload():
    store = RetestRunStore()
    with pytest.raises(ValueError):
        # invalid status → retest_run_to_json rejects before any write
        store.save_retest_run(dict(_run(status="pending"), status="weird"))


def test_list_filter_by_engagement_and_project():
    store = RetestRunStore()
    a = store.save_retest_run(_run(project="a.io", created_at="t1"))
    b = store.save_retest_run(_run(project="b.io", created_at="t2"))
    # all
    assert {r["id"] for r in store.list_retest_runs()} == {a["id"], b["id"]}
    # by project
    only_a = store.list_retest_runs(project="a.io")
    assert [r["id"] for r in only_a] == [a["id"]]
    # by engagement
    by_eng = store.list_retest_runs(engagement_id=a["engagement_id"])
    assert [r["id"] for r in by_eng] == [a["id"]]
    # AND combination that matches nothing
    assert store.list_retest_runs(engagement_id=a["engagement_id"],
                                  project="b.io") == []


def test_list_newest_snapshot_first():
    store = RetestRunStore()
    old = store.save_retest_run(_run(created_at="2026-07-01T00:00:00Z"))
    new = store.save_retest_run(_run(created_at="2026-07-05T00:00:00Z"))
    ordered = [r["id"] for r in store.list_retest_runs()]
    assert ordered == [new["id"], old["id"]]


def test_delete():
    store = RetestRunStore()
    saved = store.save_retest_run(_run())
    assert store.delete_retest_run(saved["id"]) is True
    assert store.get_retest_run(saved["id"]) is None
    assert store.delete_retest_run("rt-nope") is False


def test_export_retest_run_is_schema_valid():
    store = RetestRunStore()
    saved = store.save_retest_run(_run(
        finding_results=[{"finding_id": "f1", "outcome": "fixed",
                          "title": "H", "severity": "low", "status": "FIXED"}]))
    exported = store.export_retest_run(saved["id"])
    assert exported["retest_run_id"] == saved["id"]
    assert exported["summary"]["fixed"] == 1
    # canonical + schema-valid: re-export via the contract is stable
    assert rr.retest_run_to_json(exported) == exported


def test_export_missing_raises():
    store = RetestRunStore()
    with pytest.raises(KeyError):
        store.export_retest_run("rt-nope")


def test_project_export_slice_shape():
    store = RetestRunStore()
    store.save_retest_run(_run(project="shop.io"))
    store.save_retest_run(_run(project="other.io", created_at="t9"))
    sl = store.export_project("shop.io")
    assert isinstance(sl["rows"], list) and len(sl["rows"]) == 1
    assert sl["events"] == []  # single-table, events-less
    assert sl["rows"][0]["project"] == "shop.io"
