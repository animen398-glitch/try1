"""Re-validation of unresolved findings (Workbench v2 F3).

Pure, deterministic, offline. This module re-checks findings that are still
unresolved (``OPEN``/``IN_PROGRESS``) and produces a *validation overlay* shaped
for ``advance_audit_phase(run, "validation", result)``. It never mutates finding
lifecycle status in :class:`~core.findings_store.FindingsStore` — suppressed
(``IGNORED``/``FALSE_POSITIVE``) and ``FIXED`` findings are excluded, so sticky
suppression is honored and nothing is resurrected. The store stays the single
source of truth; this is an overlay, not a second findings store.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from core.finding_quality import apply_quality_gate
from core.finding_validation import validate_finding


EvidenceResolver = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


def _finding_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt a FindingsStore row into a validation-ready finding dict."""
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    finding_id = str(row.get("id") or row.get("finding_id") or "").strip()
    refs: List[str] = []
    for value in (evidence.get("evidence_refs") or evidence.get("refs") or []):
        if value:
            refs.append(str(value))
    out: Dict[str, Any] = {
        "finding_id": finding_id,
        "category": row.get("category"),
        "rule_id": row.get("rule_id"),
        "title": row.get("title"),
        "severity": row.get("severity"),
        "status": row.get("status"),
        "evidence": evidence or None,
        "evidence_refs": sorted(set(refs)),
    }
    location = evidence.get("location") or row.get("location")
    if location:
        out["location"] = location
    asset = evidence.get("asset") or row.get("asset") or row.get("affected_asset")
    if asset:
        out["asset"] = asset
    confidence = row.get("confidence")
    if confidence is None:
        confidence = evidence.get("confidence")
    if confidence is not None:
        out["confidence"] = confidence
    return out


def collect_unresolved(
    project: str,
    *,
    store: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Unresolved findings for a project, adapted for re-validation.

    Returns findings whose status is ``OPEN``/``IN_PROGRESS`` only; ``FIXED`` and
    suppressed findings are excluded by :meth:`FindingsStore.active_findings`.
    """
    clean_project = str(project or "").strip()
    if not clean_project:
        return []
    active_store = store
    if active_store is None:
        from core.findings_store import FindingsStore

        active_store = FindingsStore()
    rows = active_store.active_findings(clean_project) or []
    out = [_finding_from_row(row) for row in rows if isinstance(row, dict)]
    return [item for item in out if item["finding_id"]]


def revalidate_findings(
    findings: List[Dict[str, Any]],
    *,
    evidence_resolver: Optional[EvidenceResolver] = None,
    min_confidence: int = 70,
) -> Dict[str, Any]:
    """Re-validate findings into a deterministic validation overlay.

    ``evidence_resolver`` optionally returns fresh evidence (e.g. artifact
    existence / reachability) for a finding; it must never raise.
    """
    validated: List[Dict[str, Any]] = []
    events: List[Dict[str, Any]] = []
    counts = {
        "total": 0,
        "verified": 0,
        "needs_review": 0,
        "rejected": 0,
        "unverified": 0,
        "evidence_missing": 0,
        "quality_passed": 0,
    }
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("finding_id") or finding.get("id") or "").strip()
        if not finding_id:
            continue
        prior_conf = finding.get("confidence")
        evidence = None
        if evidence_resolver is not None:
            try:
                evidence = evidence_resolver(finding)
            except Exception:
                evidence = None
        row = validate_finding(finding, evidence)
        row["finding_id"] = finding_id
        row.setdefault("evidence_refs", [])
        row = apply_quality_gate(row, min_confidence=int(min_confidence))

        status = row.get("validation_status", "unverified")
        counts["total"] += 1
        counts[status] = counts.get(status, 0) + 1
        if row.get("quality_gate") == "passed":
            counts["quality_passed"] += 1

        events.append(
            {
                "type": "finding_revalidated",
                "finding_id": finding_id,
                "to_status": status,
                "confidence": int(row.get("confidence", 0)),
            }
        )
        if not row.get("evidence_refs"):
            counts["evidence_missing"] += 1
            events.append({"type": "evidence_missing", "finding_id": finding_id})
        if (
            prior_conf is not None
            and int(_safe_int(prior_conf)) != int(row.get("confidence", 0))
        ):
            events.append(
                {
                    "type": "confidence_changed",
                    "finding_id": finding_id,
                    "from": int(_safe_int(prior_conf)),
                    "to": int(row.get("confidence", 0)),
                }
            )
        validated.append(row)

    validated.sort(key=lambda item: item["finding_id"])
    events.sort(key=lambda item: (item["finding_id"], item["type"]))
    return {"validated_findings": validated, "events": events, "summary": counts}


def revalidation_phase_result(
    project: str,
    *,
    store: Optional[Any] = None,
    evidence_resolver: Optional[EvidenceResolver] = None,
    min_confidence: int = 70,
) -> Dict[str, Any]:
    """Collect unresolved findings and re-validate them in one call."""
    findings = collect_unresolved(project, store=store)
    return revalidate_findings(
        findings,
        evidence_resolver=evidence_resolver,
        min_confidence=min_confidence,
    )


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
