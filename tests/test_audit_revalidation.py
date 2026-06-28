"""Contract tests for Workbench v2 F3 — re-validation of unresolved findings."""

from core.audit_revalidation import (
    collect_unresolved,
    revalidate_findings,
    revalidation_phase_result,
)
from core.audit_schema import validate_audit_payload
from core.audit_workflow import advance_audit_phase, audit_run_to_json, create_audit_run
from core.findings_store import FindingsStore


def _seed(store: FindingsStore):
    ids = {}
    for key, sev, status in [
        ("open", "high", "OPEN"),
        ("inprog", "medium", "IN_PROGRESS"),
        ("fixed", "high", "FIXED"),
        ("ignored", "low", "IGNORED"),
        ("fp", "high", "FALSE_POSITIVE"),
    ]:
        finding = {
            "id": f"fp-{key}",
            "category": "header",
            "title": f"Issue {key}",
            "severity": sev,
            "evidence": {"location": "https://example.com/", "evidence_refs": [f"ref-{key}"]},
        }
        res = store.upsert("example.com", finding)
        scoped = res["finding"]["id"]
        ids[key] = scoped
        if status != "OPEN":
            store.set_status(scoped, status, source="user")
    return ids


def test_collect_unresolved_excludes_fixed_and_suppressed(tmp_path):
    store = FindingsStore(tmp_path / "findings.db")
    _seed(store)
    unresolved = collect_unresolved("example.com", store=store)
    titles = {f["title"] for f in unresolved}
    assert titles == {"Issue open", "Issue inprog"}
    # sticky suppression honored: nothing FIXED/IGNORED/FALSE_POSITIVE resurfaces
    assert all(f["finding_id"] for f in unresolved)


def test_revalidate_findings_overlay_is_deterministic_and_schema_valid():
    findings = [
        {"finding_id": "b", "confidence": 90, "location": "https://x/",
         "evidence_refs": ["r1"]},
        {"finding_id": "a", "confidence": 80},  # no evidence, no location
    ]
    result = revalidate_findings(findings)
    ids = [f["finding_id"] for f in result["validated_findings"]]
    assert ids == ["a", "b"]  # sorted, deterministic

    by_id = {f["finding_id"]: f for f in result["validated_findings"]}
    # 'a' has no evidence -> rejected, evidence_refs present (empty)
    assert by_id["a"]["validation_status"] == "rejected"
    assert by_id["a"]["evidence_refs"] == []
    # each validated finding conforms to the validation schema
    for finding in result["validated_findings"]:
        validate_audit_payload(finding, "asa_validation")

    assert result["summary"]["total"] == 2
    assert result["summary"]["evidence_missing"] == 1
    types = {e["type"] for e in result["events"]}
    assert "finding_revalidated" in types and "evidence_missing" in types


def test_evidence_resolver_lowers_confidence_to_needs_review():
    findings = [{"finding_id": "x", "confidence": 95, "location": "https://x/",
                 "evidence_refs": ["r1"]}]
    # resolver reports the target unreachable -> validate_finding caps confidence
    result = revalidate_findings(
        findings, evidence_resolver=lambda f: {"reachable": False}
    )
    row = result["validated_findings"][0]
    assert row["validation_status"] == "needs_review"
    assert any(e["type"] == "confidence_changed" for e in result["events"])


def test_resolver_exception_is_swallowed():
    def boom(_finding):
        raise RuntimeError("resolver failed")

    result = revalidate_findings(
        [{"finding_id": "x", "confidence": 80, "location": "https://x/",
          "evidence_refs": ["r1"]}],
        evidence_resolver=boom,
    )
    assert result["summary"]["total"] == 1


def test_phase_result_feeds_advance_audit_phase(tmp_path):
    store = FindingsStore(tmp_path / "findings.db")
    _seed(store)
    result = revalidation_phase_result("example.com", store=store)

    run = create_audit_run("example.com", template="evidence_refresh",
                           run_id="audit-f3")
    run = advance_audit_phase(run, "validation", result)
    exported = audit_run_to_json(run)
    # validated findings merged into the run by finding_id, no lifecycle writes
    assert len(exported["findings"]) == len(result["validated_findings"]) == 2
