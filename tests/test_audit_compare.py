"""Contract tests for Workbench v2 F4 — Audit Run A/B comparison."""

from core.audit_compare import (
    compare_gate,
    compare_runs,
    compare_stored,
    resolve_baseline_id,
)
from core.audit_schema import validate_audit_payload
from core.audit_store import AuditRunStore
from core.audit_workflow import advance_audit_phase, create_audit_run


def _run(run_id, findings, *, status_phase_failed=False):
    run = {
        "run_id": run_id,
        "project": "example.com",
        "profile": "client_safe",
        "status": "completed",
        "phases": [
            {"name": "validation",
             "status": "failed" if status_phase_failed else "completed",
             "result": None}
        ],
        "findings": findings,
        "events": [],
    }
    return run


def _f(fid, severity, validation="verified", title="x"):
    return {"finding_id": fid, "severity": severity,
            "validation_status": validation, "title": title}


def test_buckets_new_resolved_regressed_improved_unchanged():
    base = _run("b", [
        _f("keep", "medium"),
        _f("gone", "high"),
        _f("up", "low"),
        _f("down", "high"),
    ])
    cand = _run("c", [
        _f("keep", "medium"),
        _f("fresh", "low"),
        _f("up", "high"),     # severity increased -> regressed
        _f("down", "low"),    # severity decreased -> improved
    ])
    diff = compare_runs(base, cand)
    assert [f["finding_id"] for f in diff["new"]] == ["fresh"]
    assert [f["finding_id"] for f in diff["resolved"]] == ["gone"]
    assert [f["finding_id"] for f in diff["regressed"]] == ["up"]
    assert [f["finding_id"] for f in diff["improved"]] == ["down"]
    assert [f["finding_id"] for f in diff["unchanged"]] == ["keep"]
    validate_audit_payload(diff, "asa_audit_compare")


def test_validation_downgrade_is_regression():
    base = _run("b", [_f("x", "medium", "verified")])
    cand = _run("c", [_f("x", "medium", "rejected")])
    diff = compare_runs(base, cand)
    assert [f["finding_id"] for f in diff["regressed"]] == ["x"]


def test_gate_fails_on_regression_and_new_critical():
    base = _run("b", [_f("x", "low")])
    cand = _run("c", [_f("x", "high"), _f("crit", "critical")])
    diff = compare_runs(base, cand)
    assert diff["gate"]["passed"] is False
    assert diff["summary"]["risk_regression"] is True

    clean = compare_runs(_run("b", [_f("x", "low")]), _run("c", [_f("x", "low")]))
    assert clean["gate"]["passed"] is True


def test_failed_phase_is_inconclusive_not_regression():
    # candidate dropped a finding but a phase failed -> NOT a clean resolution
    base = _run("b", [_f("x", "high")])
    cand = _run("c", [], status_phase_failed=True)
    diff = compare_runs(base, cand)
    assert diff["inconclusive"] is True
    # a failed phase alone must not fail the gate (decision #4)
    assert diff["gate"]["passed"] is True
    assert any("inconclusive" in note for note in diff["gate"]["notes"])


def test_gate_token_new_high_optional():
    diff = compare_runs(_run("b", []), _run("c", [_f("h", "high")]))
    assert compare_gate(diff, fail_on=("new_high",))["passed"] is False
    assert compare_gate(diff, fail_on=("regressed",))["passed"] is True


def test_compare_stored_via_audit_run_store(tmp_path):
    store = AuditRunStore(tmp_path / "audit.db")
    base = create_audit_run("example.com", phases=["validation"], run_id="audit-base")
    base = advance_audit_phase(base, "validation", {"validated_findings": [
        {"finding_id": "x", "severity": "high", "validation_status": "verified"}]})
    cand = create_audit_run("example.com", phases=["validation"], run_id="audit-cand",
                            baseline_run_id="audit-base")
    cand = advance_audit_phase(cand, "validation", {"validated_findings": []})
    store.save_run(base)
    store.save_run(cand)

    assert resolve_baseline_id(cand) == "audit-base"
    diff = compare_stored(store, "audit-base", "audit-cand")
    assert [f["finding_id"] for f in diff["resolved"]] == ["x"]
    validate_audit_payload(diff, "asa_audit_compare")
