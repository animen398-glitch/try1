"""Offline tests for the orchestration stores + dispatcher (Roadmap E8 inc-2)."""

import pytest

from core.job_dispatcher import dispatch_next, run_job
from core.job_store import JobStore, NodeStore
from core.orchestration import assign_job, create_job, register_node


def _jobstore(tmp_path):
    return JobStore(tmp_path / "jobs.db")


def _nodestore(tmp_path):
    return NodeStore(tmp_path / "nodes.db")


def _node(**over):
    opts = dict(capabilities=["audit_run"], authorized=True)
    opts.update(over)
    return register_node("runner-1", **opts)


# --- JobStore ----------------------------------------------------------------

def test_save_and_get_job(tmp_path):
    store = _jobstore(tmp_path)
    job = create_job("audit_run", project="p", target="t", created_at="t0")
    saved = store.save_job(job)
    assert saved["status"] == "pending"
    fetched = store.get_job(job["job_id"])
    assert fetched["payload"]["kind"] == "audit_run"
    assert fetched["project"] == "p"


def test_save_job_idempotent_preserves_created_at(tmp_path):
    store = _jobstore(tmp_path)
    job = create_job("audit_run", created_at="t0")
    first = store.save_job(job, now="2026-07-01T00:00:00")
    again = store.save_job(job, now="2026-07-02T00:00:00")
    assert again["created_at"] == first["created_at"]
    assert again["updated_at"] != first["updated_at"]


def test_list_jobs_filters_and_orders(tmp_path):
    store = _jobstore(tmp_path)
    store.save_job(create_job("audit_run", target="lo", priority=0, created_at="t2"))
    store.save_job(create_job("audit_run", target="hi", priority=9, created_at="t3"))
    store.save_job(create_job("tool_run", target="tool", priority=1, created_at="t1"))
    all_jobs = store.list_jobs()
    assert all_jobs[0]["payload"]["target"] == "hi"  # highest priority first
    assert [j["payload"]["target"] for j in store.list_jobs(status="pending")]
    assert len(store.list_jobs(project="")) == 3


def test_delete_job(tmp_path):
    store = _jobstore(tmp_path)
    job = create_job("audit_run")
    store.save_job(job)
    assert store.delete_job(job["job_id"]) is True
    assert store.get_job(job["job_id"]) is None


def test_save_job_rejects_bad_status(tmp_path):
    store = _jobstore(tmp_path)
    with pytest.raises(ValueError):
        store.save_job({"kind": "audit_run", "status": "bogus"})


def test_claim_next_job_persists_claim(tmp_path):
    store = _jobstore(tmp_path)
    store.save_job(create_job("audit_run", target="a", priority=1, created_at="t1"))
    store.save_job(create_job("audit_run", target="b", priority=5, created_at="t2"))
    node = _node()
    claimed = store.claim_next_job(node)
    assert claimed["payload"]["target"] == "b"          # highest priority
    assert claimed["status"] == "claimed"
    assert claimed["node_id"] == node["node_id"]
    # persisted: it is no longer pending
    assert store.get_job(claimed["id"])["status"] == "claimed"


def test_claim_next_job_none_for_incapable_node(tmp_path):
    store = _jobstore(tmp_path)
    store.save_job(create_job("tool_run"))
    assert store.claim_next_job(_node(capabilities=["audit_run"])) is None


# --- NodeStore ---------------------------------------------------------------

def test_save_and_list_nodes(tmp_path):
    store = _nodestore(tmp_path)
    store.save_node(register_node("a", capabilities=["audit_run"], authorized=True))
    store.save_node(register_node("b", authorized=False))
    assert len(store.list_nodes()) == 2
    authorized = store.list_nodes(authorized=True)
    assert len(authorized) == 1
    assert authorized[0]["payload"]["label"] == "a"


def test_delete_node(tmp_path):
    store = _nodestore(tmp_path)
    node = register_node("a", authorized=True)
    store.save_node(node)
    assert store.delete_node(node["node_id"]) is True
    assert store.get_node(node["node_id"]) is None


# --- dispatcher --------------------------------------------------------------

def _claimed(tmp_path):
    store = _jobstore(tmp_path)
    job = create_job("audit_run", target="t", created_at="t0")
    store.save_job(job)
    claimed = assign_job(job, _node())
    return store, store.save_job(claimed)


def test_run_job_completes_with_result_ref(tmp_path):
    store, claimed = _claimed(tmp_path)
    runners = {"audit_run": lambda j: "audit-123"}
    out = run_job(claimed, runners, store=store)
    assert out["status"] == "completed"
    assert out["result_ref"] == "audit-123"
    assert store.get_job(out["job_id"])["status"] == "completed"


def test_run_job_no_runner_fails_softly(tmp_path):
    store, claimed = _claimed(tmp_path)
    out = run_job(claimed, {}, store=store)
    assert out["status"] == "failed"
    assert "no runner" in out["_error"]
    assert store.get_job(claimed["id"])["status"] == "failed"


def test_run_job_runner_error_fails_softly(tmp_path):
    store, claimed = _claimed(tmp_path)

    def boom(job):
        raise RuntimeError("scan crashed")

    out = run_job(claimed, {"audit_run": boom}, store=store)
    assert out["status"] == "failed"
    assert out["_error"] == "scan crashed"


def test_run_job_requires_claimed():
    with pytest.raises(ValueError):
        run_job(create_job("audit_run"), {"audit_run": lambda j: "x"})


def test_dispatch_next_claims_and_runs(tmp_path):
    store = _jobstore(tmp_path)
    store.save_job(create_job("audit_run", target="t", created_at="t0"))
    node = _node()
    ran = {}
    runners = {"audit_run": lambda j: ran.setdefault("ref", "audit-9") or "audit-9"}
    out = dispatch_next(node, runners, store=store)
    assert out["status"] == "completed"
    assert out["result_ref"] == "audit-9"
    # queue drained → nothing left to claim
    assert dispatch_next(node, runners, store=store) is None
