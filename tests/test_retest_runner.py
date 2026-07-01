"""core/retest_runner.py — take + persist a retest snapshot (R3).

Offline: reuses engagement_retest.build_retest for outcomes and RetestRunStore
for persistence (both conftest-isolated). No network, no tool execution.
"""

import pytest

from core import engagement as eng
from core import retest_runner
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.retest_run_store import RetestRunStore


def _finding(rule_id, location, *, status=None):
    fs = FindingsStore()
    fid = fs.upsert("shop.io", Finding(
        category="vuln", rule_id=rule_id, title=f"f-{rule_id}", severity="high",
        location=location).to_store(), scan_id="s1")["finding"]["id"]
    if status:
        fs.set_status(fid, status)
    return fid


def _engagement_with_findings():
    fixed = _finding("r1", "https://shop.io/1", status="FIXED")
    open_ = _finding("r2", "https://shop.io/2")
    e = eng.create_engagement("Acme Corp", "shop.io")
    e = eng.link_finding(e, fixed)
    e = eng.link_finding(e, open_)
    e = eng.link_finding(e, "ghost")           # missing
    return e


def test_run_retest_snapshots_and_persists_completed():
    e = _engagement_with_findings()
    out = retest_runner.run_retest(e, now="2026-07-01T10:00:00Z")
    assert out["status"] == "completed"
    assert out["retest_run_id"].startswith("rt-")
    assert out["summary"] == {"total": 3, "fixed": 1, "open": 1,
                              "accepted": 0, "missing": 1}
    # persisted + retrievable
    store = RetestRunStore()
    row = store.get_retest_run(out["retest_run_id"])
    assert row is not None
    assert row["status"] == "completed"
    assert row["payload"]["engagement_id"] == e["engagement_id"]


def test_run_retest_snapshot_is_frozen_not_live():
    """A completed snapshot keeps the outcome at run time even if the finding
    later changes — that's the whole point of a persisted run."""
    fid = _finding("r1", "https://shop.io/1")            # OPEN at run time
    e = eng.link_finding(eng.create_engagement("Acme", "shop.io"), fid)
    out = retest_runner.run_retest(e, now="t1")
    assert out["summary"]["open"] == 1 and out["summary"]["fixed"] == 0
    # remediate the finding afterwards
    FindingsStore().set_status(fid, "FIXED")
    frozen = RetestRunStore().get_retest_run(out["retest_run_id"])
    results = frozen["payload"]["finding_results"]
    assert results[0]["outcome"] == "open"               # snapshot unchanged


def test_two_runs_are_distinct_records():
    e = _engagement_with_findings()
    a = retest_runner.run_retest(e, now="2026-07-01T10:00:00Z")
    b = retest_runner.run_retest(e, now="2026-07-05T10:00:00Z")
    assert a["retest_run_id"] != b["retest_run_id"]
    runs = RetestRunStore().list_retest_runs(engagement_id=e["engagement_id"])
    assert [r["id"] for r in runs] == [b["retest_run_id"], a["retest_run_id"]]


def test_engagement_id_required():
    with pytest.raises(ValueError, match="engagement_id is required"):
        retest_runner.run_retest({"client": "", "project": ""})


def test_empty_engagement_completes_with_zero_findings():
    e = eng.create_engagement("Acme", "shop.io")
    out = retest_runner.run_retest(e, now="t1")
    assert out["status"] == "completed"
    assert out["summary"]["total"] == 0


class _RaisingStore:
    def get(self, _fid):
        raise RuntimeError("findings store is down")


def test_failure_persists_failed_run_and_reraises():
    e = eng.link_finding(eng.create_engagement("Acme", "shop.io"), "f1")
    with pytest.raises(RuntimeError, match="findings store is down"):
        retest_runner.run_retest(e, now="2026-07-01T10:00:00Z",
                                 findings_store=_RaisingStore())
    # a failed run was persisted (never stuck in 'pending')
    runs = RetestRunStore().list_retest_runs(engagement_id=e["engagement_id"])
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"


def test_injected_store_is_used():
    e = _engagement_with_findings()
    injected = RetestRunStore()
    retest_runner.run_retest(e, now="t1", retest_store=injected)
    assert len(injected.list_retest_runs()) == 1
