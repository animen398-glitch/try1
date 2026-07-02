"""Offline tests for Authorized Worker Orchestration (Roadmap E8)."""

import pytest

from core.audit_schema import validate_audit_payload
from core.orchestration import (
    JOB_KINDS,
    advance_job_status,
    assign_job,
    claim_next,
    create_job,
    job_to_json,
    node_can_run,
    node_to_json,
    normalize_job,
    register_node,
    validate_job,
)


# --- nodes -------------------------------------------------------------------

def test_register_node_defaults_inert():
    n = register_node("box-a")
    assert n["node_id"].startswith("node-")
    assert n["authorized"] is False
    assert n["status"] == "active"
    assert n["capabilities"] == []


def test_register_node_rejects_bad_capability():
    with pytest.raises(ValueError):
        register_node("box", capabilities=["exploit_everything"])


def test_register_node_requires_label():
    with pytest.raises(ValueError):
        register_node("  ")


def test_node_can_run_requires_authorized_active_capable():
    ok = register_node("n", capabilities=["audit_run"], authorized=True)
    assert node_can_run(ok, "audit_run") is True
    assert node_can_run(ok, "tool_run") is False  # capability not declared
    assert node_can_run(register_node("n", capabilities=["audit_run"]),
                        "audit_run") is False       # not authorized
    draining = register_node("n", capabilities=["audit_run"], authorized=True,
                             status="draining")
    assert node_can_run(draining, "audit_run") is False


# --- jobs --------------------------------------------------------------------

def test_create_job_is_pending_and_kinded():
    j = create_job("full_collection", target="example.com", created_at="2026-07-01")
    assert j["job_id"].startswith("job-")
    assert j["status"] == "pending"
    assert j["kind"] == "full_collection"
    assert j["node_id"] == ""


def test_create_job_rejects_unknown_kind():
    with pytest.raises(ValueError):
        create_job("mine_bitcoin")


def test_all_kinds_are_creatable():
    for kind in JOB_KINDS:
        assert create_job(kind)["kind"] == kind


def test_validate_claimed_job_needs_node():
    j = normalize_job({"kind": "audit_run", "status": "claimed", "node_id": ""})
    result = validate_job(j)
    assert result["valid"] is False
    assert any("assigned to a node" in e for e in result["errors"])


# --- transitions -------------------------------------------------------------

def test_legal_transition():
    j = create_job("audit_run", created_at="t0")
    claimed = advance_job_status(j, "claimed", now="t1")
    assert claimed["status"] == "claimed"
    assert claimed["updated_at"] == "t1"


def test_illegal_transition_raises():
    j = create_job("audit_run")
    with pytest.raises(ValueError):
        advance_job_status(j, "completed")  # pending -> completed is illegal


def test_release_clears_node():
    j = create_job("audit_run")
    node = register_node("n", capabilities=["audit_run"], authorized=True)
    claimed = assign_job(j, node)
    released = advance_job_status(claimed, "pending")
    assert released["node_id"] == ""


# --- assignment (authorization gate) -----------------------------------------

def test_assign_to_authorized_capable_node():
    j = create_job("audit_run")
    node = register_node("n", capabilities=["audit_run"], authorized=True)
    claimed = assign_job(j, node)
    assert claimed["status"] == "claimed"
    assert claimed["node_id"] == node["node_id"]


def test_assign_refuses_unauthorized_node():
    j = create_job("audit_run")
    node = register_node("n", capabilities=["audit_run"], authorized=False)
    with pytest.raises(ValueError):
        assign_job(j, node)


def test_assign_refuses_incapable_node():
    j = create_job("tool_run")
    node = register_node("n", capabilities=["audit_run"], authorized=True)
    with pytest.raises(ValueError):
        assign_job(j, node)


def test_assign_only_pending():
    j = advance_job_status(create_job("audit_run"), "cancelled")
    node = register_node("n", capabilities=["audit_run"], authorized=True)
    with pytest.raises(ValueError):
        assign_job(j, node)


# --- scheduler (claim_next) --------------------------------------------------

def test_claim_next_prefers_priority_then_age():
    node = register_node("n", capabilities=["audit_run"], authorized=True)
    jobs = [
        create_job("audit_run", target="a", priority=0, created_at="t2"),
        create_job("audit_run", target="b", priority=5, created_at="t3"),
        create_job("audit_run", target="c", priority=5, created_at="t1"),  # older
    ]
    pick = claim_next(jobs, node)
    assert pick["target"] == "c"  # highest priority, oldest


def test_claim_next_skips_incapable_and_nonpending():
    node = register_node("n", capabilities=["tool_run"], authorized=True)
    jobs = [
        create_job("audit_run", target="a"),                 # wrong kind
        advance_job_status(create_job("tool_run", target="b"), "cancelled"),
        create_job("tool_run", target="c", created_at="t1"),  # the only eligible
    ]
    assert claim_next(jobs, node)["target"] == "c"


def test_claim_next_none_when_no_eligible():
    node = register_node("n", capabilities=["audit_run"], authorized=True)
    assert claim_next([], node) is None
    assert claim_next([create_job("tool_run")], node) is None


# --- schema ------------------------------------------------------------------

def test_job_to_json_is_schema_valid():
    validate_audit_payload(job_to_json(create_job("mission_run", project="p")),
                           "asa_job")


def test_node_to_json_is_schema_valid():
    node = register_node("n", capabilities=["mission_run"], authorized=True)
    validate_audit_payload(node_to_json(node), "asa_worker_node")
