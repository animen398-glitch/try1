"""Audit Runs GUI tab - headless thin surface tests."""

import json

from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from gui.plugin_manager import default_manager
from gui.tab_audit_runs import AuditRunsTabMixin
from tests.gui_test_helpers import AuditRunsHost


def _window(qapp):
    return AuditRunsHost()


def _seed_finding(project="shop.com", *, evidence=None):
    store = FindingsStore()
    dto = Finding(
        category="vuln",
        rule_id="edge",
        title="Exposed source map",
        severity="critical",
        location="https://shop.com/app.js.map",
    ).to_store()
    dto["evidence"] = evidence or {}
    return store.upsert(project, dto, scan_id="s1")["finding"]["id"]


def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, "_audit_widget")
    assert w.audit_findings.columnCount() == len(AuditRunsTabMixin.AUDIT_COLUMNS)
    assert w.audit_progress.maximum() > 0


def test_audit_runs_registered_in_tab_bar(qapp):
    titles = [p.title for p in default_manager()]
    assert "Audit Runs" in titles


def test_query_projects_lists_finding_projects(qapp):
    _seed_finding("shop.com")
    out = AuditRunsTabMixin._query_audit_projects()
    assert "shop.com" in {p["project"] for p in out["projects"]}


def test_start_run_builds_deterministic_audit_payload(qapp):
    _seed_finding(
        "shop.com",
        evidence={
            "location": "https://shop.com/app.js.map",
            "asset": "https://shop.com",
            "impact": "Source disclosure.",
            "remediation": "Remove source maps.",
            "reachability": "public",
            "evidence_refs": ["capture/app-map.json"],
            "confidence": 90,
        },
    )

    first = AuditRunsTabMixin._query_audit_run("shop.com")
    second = AuditRunsTabMixin._query_audit_run("shop.com")

    assert first["run"]["status"] == "completed"
    assert len(first["rows"]) == 1
    finding = first["rows"][0]["finding"]
    assert finding["validation_status"] == "verified"
    assert finding["quality_gate"] == "passed"
    assert json.dumps(first["run"], sort_keys=True) == json.dumps(second["run"], sort_keys=True)


def test_run_without_evidence_shows_rejected_and_failed_gate(qapp):
    _seed_finding("shop.com", evidence={})

    out = AuditRunsTabMixin._query_audit_run("shop.com")
    finding = out["rows"][0]["finding"]

    assert finding["validation_status"] == "rejected"
    assert finding["quality_gate"] == "failed"


def test_populate_run_updates_phase_progress_rollup_and_table(qapp):
    w = _window(qapp)
    out = {
        "run": {
            "run_id": "audit-x",
            "project": "shop.com",
            "profile": "client_safe",
            "status": "completed",
            "phases": [
                {"name": "recon_snapshot", "status": "completed", "result": {"active_findings": 1}},
                {"name": "finding_hunt", "status": "completed", "result": {"findings": []}},
            ],
        },
        "rows": [
            {
                "finding": {
                    "title": "Missing header",
                    "severity": "high",
                    "validation_status": "needs_review",
                    "confidence": 60,
                    "quality_gate": "failed",
                    "asset": "https://shop.com",
                    "location": "https://shop.com",
                    "quality_reasons": ["confidence below threshold"],
                },
                "evidence_refs": ["evidence/http.json"],
            }
        ],
    }

    w._audit_run = out["run"]
    w._audit_rows = out["rows"]
    w._populate_audit_run(out["run"], out["rows"])

    assert w.audit_progress.value() == 2
    assert w.audit_findings.rowCount() == 1
    assert w.audit_rollup["needs_review"].text() == "1"
    assert w.audit_rollup["quality_failed"].text() == "1"


def test_selection_shows_evidence_refs(qapp):
    w = _window(qapp)
    rows = [
        {
            "finding": {
                "title": "Missing header",
                "severity": "high",
                "validation_status": "verified",
                "confidence": 80,
                "quality_gate": "passed",
                "asset": "https://shop.com",
                "location": "https://shop.com",
            },
            "evidence_refs": ["evidence/http.json"],
        }
    ]
    w._audit_rows = rows
    w._populate_audit_findings(rows)

    w.audit_findings.selectRow(0)

    assert "evidence/http.json" in w.audit_detail.toPlainText()


def test_audit_json_payload_is_sorted_and_valid(qapp):
    run = AuditRunsTabMixin._query_audit_run("empty-project")["run"]
    payload = AuditRunsTabMixin._audit_json_payload(run)
    assert json.loads(payload)["project"] == "empty-project"
    assert payload == AuditRunsTabMixin._audit_json_payload(run)
