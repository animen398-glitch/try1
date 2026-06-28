"""Workbench v2 thin-GUI surface tests for the Audit Runs tab."""

from core.audit_store import AuditRunStore
from core.audit_workflow import advance_audit_phase, create_audit_run
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from gui.tab_audit_runs import AuditRunsTabMixin
from tests.gui_test_helpers import AuditRunsHost


def _seed_finding(project="shop.com"):
    store = FindingsStore()
    dto = Finding(category="vuln", rule_id="edge", title="Exposed source map",
                  severity="critical", location="https://shop.com/app.js.map").to_store()
    dto["evidence"] = {"location": "https://shop.com/app.js.map", "asset": "https://shop.com",
                       "impact": "x", "remediation": "y", "reachability": "public",
                       "evidence_refs": ["capture/app-map.json"], "confidence": 90}
    return store.upsert(project, dto, scan_id="s1")["finding"]["id"]


def _save_run(run_id, findings):
    run = create_audit_run("shop.com", phases=["validation"], run_id=run_id)
    run = advance_audit_phase(run, "validation", {"validated_findings": findings})
    AuditRunStore().save_run(run)
    return run


def test_tab_has_scenario_and_compare_controls(qapp):
    w = AuditRunsHost()
    # scenario combo: Full + 4 templates
    labels = [w.audit_template.itemData(i) for i in range(w.audit_template.count())]
    assert "" in labels
    assert {"light_client_safe", "authenticated_review", "evidence_refresh",
            "release_regression"} <= set(labels)
    assert hasattr(w, "audit_baseline")
    assert not w.btn_audit_compare.isEnabled()
    assert not w.btn_audit_compare_export.isEnabled()


def test_query_audit_run_template_uses_phase_subset(qapp):
    _seed_finding("shop.com")
    out = AuditRunsTabMixin._query_audit_run(
        "shop.com", run_id="audit-v2-light", template="light_client_safe"
    )
    assert "error" not in out
    run = out["run"]
    assert run["template"] == "light_client_safe"
    phase_names = [p["name"] for p in run["phases"]]
    assert phase_names == ["recon_snapshot", "finding_hunt", "validation",
                           "structured_output"]
    # ROE bound from the scenario's roe_template
    assert run["roe"]["passive_only"] is True


def test_query_audit_compare_returns_diff(qapp):
    _save_run("audit-base", [{"finding_id": "x", "severity": "high",
                              "validation_status": "verified"}])
    _save_run("audit-cand", [])
    out = AuditRunsTabMixin._query_audit_compare("audit-base", "audit-cand")
    assert "error" not in out
    assert [f["finding_id"] for f in out["diff"]["resolved"]] == ["x"]


def test_update_compare_enabled_requires_current_and_baseline(qapp):
    w = AuditRunsHost()
    w._audit_run = {}
    w._update_compare_enabled()
    assert not w.btn_audit_compare.isEnabled()
    # populate history (also fills baseline combo)
    w._populate_audit_history([{"updated_at": "t", "id": "audit-base", "status": "completed"}])
    w._audit_run = {"run_id": "audit-cand"}
    w._update_compare_enabled()
    assert w.btn_audit_compare.isEnabled()
