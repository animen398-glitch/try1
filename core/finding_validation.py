"""Deterministic finding validation for client-safe audit runs."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Optional


VALIDATION_STATUSES = {"unverified", "verified", "rejected", "needs_review"}


def _confidence(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _evidence_refs(finding: Dict[str, Any], evidence: Optional[Dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for value in finding.get("evidence_refs") or []:
        if value:
            refs.append(str(value))
    if isinstance(evidence, dict):
        for value in evidence.get("refs") or evidence.get("evidence_refs") or []:
            if value:
                refs.append(str(value))
    return sorted(set(refs))


def validate_finding(
    finding: Dict[str, Any],
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate evidence presence and context without network side effects."""
    row = deepcopy(finding)
    reasons: list[str] = []
    confidence = _confidence(row.get("confidence", 0))
    refs = _evidence_refs(row, evidence)
    if refs:
        row["evidence_refs"] = refs
    else:
        reasons.append("missing evidence")
        confidence = min(confidence, 50)

    if not (row.get("asset") or row.get("affected_asset") or row.get("location")):
        reasons.append("missing affected asset or location")
        confidence = min(confidence, 55)

    if isinstance(evidence, dict) and evidence.get("reachable") is False:
        reasons.append("evidence target is not reachable")
        confidence = min(confidence, 60)

    if reasons:
        status = "rejected" if "missing evidence" in reasons else "needs_review"
    elif confidence >= 70:
        status = "verified"
    else:
        status = "needs_review"
    row["confidence"] = confidence
    row["validation_status"] = status
    row["validation_reasons"] = sorted(reasons)
    return row
