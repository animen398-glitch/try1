"""Web console Audit Runs read parity (remote/web_app.py, Workbench v2)."""

import pytest

import remote.web_app as wa
from core.audit_store import AuditRunStore
from core.audit_workflow import advance_audit_phase, create_audit_run


def _save_run(run_id, findings):
    run = create_audit_run("shop.com", phases=["validation"], run_id=run_id)
    run = advance_audit_phase(run, "validation", {"validated_findings": findings})
    AuditRunStore().save_run(run)


def test_audit_runs_list_helper():
    _save_run("audit-a", [{"finding_id": "x", "severity": "high",
                           "validation_status": "verified"}])
    out = wa._audit_runs_list("shop.com")
    assert "error" not in out
    assert {r["run_id"] for r in out["runs"]} == {"audit-a"}


def test_audit_run_view_unknown_is_not_found():
    out = wa._audit_run_view("nope")
    assert "not found" in out.get("error", "")


def test_audit_compare_helper():
    _save_run("audit-base", [{"finding_id": "x", "severity": "high",
                              "validation_status": "verified"}])
    _save_run("audit-cand", [])
    diff = wa._audit_compare_view("audit-base", "audit-cand")
    assert "error" not in diff
    assert [f["finding_id"] for f in diff["resolved"]] == ["x"]


def test_audit_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient

    _save_run("audit-base", [{"finding_id": "x", "severity": "high",
                              "validation_status": "verified"}])
    _save_run("audit-cand", [])
    client = TestClient(wa.app)

    r = client.get("/audit-runs", params={"project": "shop.com"})
    assert r.status_code == 200
    assert {row["run_id"] for row in r.json()["runs"]} == {"audit-base", "audit-cand"}

    r = client.get("/audit-runs/audit-base")
    assert r.status_code == 200 and r.json()["run"]["run_id"] == "audit-base"

    r = client.get("/audit-runs/missing")
    assert r.status_code == 404

    r = client.get("/audit-compare", params={"baseline": "audit-base",
                                             "candidate": "audit-cand"})
    assert r.status_code == 200
    assert [f["finding_id"] for f in r.json()["resolved"]] == ["x"]
