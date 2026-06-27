"""Quality gate for client-facing audit findings."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


def _confidence(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _has_evidence(finding: Dict[str, Any]) -> bool:
    return bool(finding.get("evidence") or finding.get("evidence_refs"))


def apply_quality_gate(
    finding: Dict[str, Any],
    *,
    min_confidence: int = 70,
) -> Dict[str, Any]:
    """Mark whether a finding is eligible for a client-facing report."""
    row = deepcopy(finding)
    reasons: list[str] = []
    if not (row.get("asset") or row.get("affected_asset") or row.get("location")):
        reasons.append("missing affected asset or location")
    if not _has_evidence(row):
        reasons.append("missing evidence")
    if not (row.get("impact") or row.get("business_impact")):
        reasons.append("missing impact")
    if not row.get("remediation"):
        reasons.append("missing remediation")
    if not (row.get("reachability") or row.get("context") or row.get("risk_context")):
        reasons.append("missing reachability or context")
    if _confidence(row.get("confidence")) < int(min_confidence):
        reasons.append("confidence below threshold")
    if row.get("validation_status") == "rejected":
        reasons.append("validation rejected")

    passed = not reasons
    row["quality_gate"] = "passed" if passed else "failed"
    row["client_facing"] = passed
    row["quality_reasons"] = sorted(reasons)
    return row
