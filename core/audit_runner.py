"""core/audit_runner.py
Client-Safe audit-run orchestration (the single source of truth).

Builds a deterministic Audit Run from a project's existing findings plus optional
safe checks: validate + quality-gate each finding, advance the audit phase
machine, persist the run, and record lifecycle events. This is the orchestration
that used to live inline in ``gui/tab_audit_runs`` — extracted so both the GUI
tab and the Mission Center runner (``core/mission_runner``) share one
implementation instead of duplicating it.

It reuses the pure pieces (``audit_workflow`` phase machine, ``audit_checks``
safe checks, ``finding_validation``/``finding_quality`` gates) and writes only to
the existing ``AuditRunStore`` — never a second store. Network I/O only happens if
a ``fetcher`` is injected (the offline default performs none).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional


def target_from_roe(project: str, roe: Dict[str, Any]) -> str:
    """The audit target host: the first ROE allowed domain, else the project."""
    allowed = (roe or {}).get("allowed_domains") or []
    host = allowed[0] if allowed else project
    if str(host).startswith(("http://", "https://")):
        return str(host)
    return f"https://{host}"


def audit_candidate(finding: Dict[str, Any]) -> Dict[str, Any]:
    """A validation candidate built from a stored finding + its evidence block."""
    evidence = finding.get("evidence") if isinstance(finding, dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}
    fid = str(finding.get("id") or "")
    evidence_refs = list(evidence.get("evidence_refs") or evidence.get("refs") or [])
    if evidence and not evidence_refs:
        evidence_refs = [f"finding:{fid}:evidence"]
    location = (
        evidence.get("location")
        or evidence.get("url")
        or evidence.get("source")
        or finding.get("location")
        or ""
    )
    asset = evidence.get("asset") or evidence.get("host") or finding.get("project") or ""
    return {
        "id": fid,
        "finding_id": fid,
        "title": finding.get("title", ""),
        "severity": str(finding.get("severity") or "info").lower(),
        "asset": asset,
        "location": location,
        "impact": evidence.get("impact") or finding.get("impact") or "",
        "business_impact": evidence.get("business_impact") or "",
        "remediation": evidence.get("remediation") or finding.get("remediation") or "",
        "reachability": evidence.get("reachability") or evidence.get("context") or "",
        "confidence": int(evidence.get("confidence") or finding.get("confidence") or 70),
        "validation_status": "unverified",
        "evidence_refs": evidence_refs,
    }


def build_audit_rows(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate + quality-gate each finding into a deterministic, sorted row list."""
    from core.finding_quality import apply_quality_gate
    from core.finding_validation import validate_finding

    rows = []
    for finding in findings:
        candidate = audit_candidate(finding)
        evidence = finding.get("evidence") if isinstance(finding, dict) else {}
        validated = validate_finding(candidate, evidence=evidence)
        gated = apply_quality_gate(validated, min_confidence=70)
        rows.append({
            "source": finding,
            "finding": gated,
            "evidence_refs": list(gated.get("evidence_refs") or []),
        })
    rows.sort(key=lambda row: (row["finding"].get("title", ""),
                               row["finding"].get("id", "")))
    return rows


def rows_from_run(run: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reconstruct display rows from a stored run's persisted findings."""
    return [
        {"finding": finding,
         "evidence_refs": list(finding.get("evidence_refs") or [])}
        for finding in (run.get("findings") or [])
        if isinstance(finding, dict)
    ]


def rollup(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Counts of validation outcomes + failed quality gates across rows."""
    out = {"verified": 0, "rejected": 0, "needs_review": 0, "quality_failed": 0}
    for row in rows:
        finding = row.get("finding") or {}
        status = finding.get("validation_status")
        if status in out:
            out[status] += 1
        if finding.get("quality_gate") == "failed":
            out["quality_failed"] += 1
    return out


def record_audit_events(store, run_id: str, rows: List[Dict[str, Any]]) -> None:
    """Record finding/quality/confidence lifecycle events once (idempotent)."""
    def clean_confidence(value: Any) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    existing = {
        (event.get("type"), event.get("phase"),
         event.get("finding_id"), event.get("note"))
        for event in store.events(run_id)
    }

    def record_once(event_type: str, *, phase: str,
                    finding_id: Optional[str], note: Dict[str, Any]):
        encoded_note = json.dumps(note, ensure_ascii=False, sort_keys=True)
        key = (event_type, phase, finding_id, encoded_note)
        if key not in existing:
            store.record_event(run_id, event_type, phase=phase,
                               finding_id=finding_id, note=note)
            existing.add(key)

    for row in rows:
        finding = row.get("finding") or {}
        source = row.get("source") or {}
        finding_id = str(finding.get("finding_id") or finding.get("id") or "").strip() or None
        status = str(finding.get("validation_status") or "").strip()
        if status in {"verified", "rejected", "needs_review"}:
            record_once(f"finding_{status}", phase="validation",
                        finding_id=finding_id,
                        note={"confidence": finding.get("confidence")})
        gate = str(finding.get("quality_gate") or "").strip()
        if gate in {"passed", "failed"}:
            record_once(f"quality_gate_{gate}", phase="risk_business_impact",
                        finding_id=finding_id,
                        note={"reasons": finding.get("quality_reasons") or []})
        source_confidence = source.get("confidence")
        if isinstance(source.get("evidence"), dict):
            source_confidence = source["evidence"].get("confidence", source_confidence)
        before = clean_confidence(source_confidence)
        after = clean_confidence(finding.get("confidence"))
        if before is not None and after is not None and before != after:
            record_once("confidence_changed", phase="validation",
                        finding_id=finding_id, note={"from": before, "to": after})


def build_audit_run(
    project: str,
    *,
    run_id: Optional[str] = None,
    roe: Optional[Dict[str, Any]] = None,
    checks: Optional[List[str]] = None,
    template: Optional[str] = None,
    evidence: Optional[Dict[str, Dict[str, Any]]] = None,
    fetcher: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build, persist and event-log a full Audit Run for ``project``.

    Reads the project's active findings, runs the selected client-safe checks
    (gated by ROE; no network unless ``fetcher`` is injected), validates and
    quality-gates each finding, advances the audit phase machine, saves to
    ``AuditRunStore`` and records lifecycle events. Returns
    ``{project, run, rows, saved}``. Raises on any failure (callers map to UX).
    """
    from core.audit_checks import run_safe_checks
    from core.audit_evidence import verify_evidence_refs
    from core.audit_scope import normalize_roe, validate_roe
    from core.audit_store import AuditRunStore
    from core.audit_workflow import (
        advance_audit_phase,
        audit_run_to_json,
        create_audit_run,
    )
    from core.findings_store import FindingsStore

    findings = FindingsStore().active_findings(project)
    normalized_roe = normalize_roe(roe)
    roe_validation = validate_roe(normalized_roe)
    check_result: Dict[str, Any] = {"results": [], "findings": []}
    if checks:
        target = target_from_roe(project, normalized_roe)
        check_result = run_safe_checks(target, normalized_roe, checks=checks,
                                       evidence=evidence, fetcher=fetcher)
    if template:
        run = create_audit_run(project, template=template, roe=normalized_roe,
                               run_id=run_id)
    else:
        run = create_audit_run(project, run_id=run_id)
    present = {
        phase.get("name")
        for phase in (run.get("phases") or [])
        if isinstance(phase, dict)
    }
    rows = build_audit_rows(findings + list(check_result.get("findings") or []))

    def advance(name: str, result: dict):
        # Templates may select a phase subset; only advance present phases.
        nonlocal run
        if name in present:
            run = advance_audit_phase(run, name, result)

    advance("recon_snapshot", {
        "project": project,
        "active_findings": len(findings),
        "roe": normalized_roe,
        "roe_valid": roe_validation["valid"],
    })
    advance("finding_hunt", {
        "findings": [row["finding"] for row in rows],
        "safe_checks": check_result.get("results", []),
    })
    advance("validation", {"validated_findings": [row["finding"] for row in rows]})
    advance("risk_business_impact", {"quality": rollup(rows)})
    advance("structured_output", {"schema": "asa_audit_run", "export": "json"})
    advance("independent_verification", {
        "evidence_refs": sorted({ref for row in rows for ref in row["evidence_refs"]}),
        "evidence_check": verify_evidence_refs(
            (ref for row in rows for ref in row["evidence_refs"]),
            findings=[row["finding"] for row in rows],
            safe_checks=check_result.get("results", []),
        ),
    })

    payload = audit_run_to_json(run)
    store = AuditRunStore()
    saved = store.save_run(payload)
    record_audit_events(store, payload["run_id"], rows)
    return {"project": project, "run": payload, "rows": rows, "saved": saved}
