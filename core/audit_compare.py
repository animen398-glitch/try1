"""Audit Run A/B comparison (Workbench v2 F4).

Pure, deterministic, stdlib-only. Compares two audit-run payloads by stable
finding identity (``finding_id`` = fingerprint) and buckets the delta into
new / resolved / regressed / improved / unchanged. Mirrors the Scan Diff rule:
a failed candidate phase makes the comparison *inconclusive* (a phase failure is
not a resolution), and the release gate never fails solely because of it.

This derives entirely from two run payloads (themselves derived from the single
FindingsStore source of truth); it introduces no second findings store and no
new table — comparison is computed on demand.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_VALIDATION_RANK = {"rejected": 0, "needs_review": 1, "unverified": 2, "verified": 3}

DEFAULT_GATE_FAIL_ON: Tuple[str, ...] = ("regressed", "new_critical")


def _severity(value: Any) -> str:
    return str(value or "").strip().lower() or "info"


def _sev_rank(value: Any) -> int:
    return _SEVERITY_RANK.get(_severity(value), 0)


def _val_rank(value: Any) -> int:
    return _VALIDATION_RANK.get(str(value or "").strip().lower(), 2)


def _index(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in (run.get("findings") or []):
        if not isinstance(item, dict):
            continue
        fid = str(item.get("finding_id") or item.get("id") or "").strip()
        if fid:
            out[fid] = item
    return out


def _ref(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "finding_id": str(finding.get("finding_id") or finding.get("id") or "").strip(),
        "title": finding.get("title", ""),
        "severity": _severity(finding.get("severity")),
        "validation_status": str(finding.get("validation_status") or "").strip(),
    }


def _candidate_has_failed_phase(run: Dict[str, Any]) -> bool:
    for phase in (run.get("phases") or []):
        if isinstance(phase, dict) and phase.get("status") == "failed":
            return True
    return str(run.get("status") or "").strip() == "failed"


def compare_runs(baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Bucket the finding-level delta between two audit-run payloads."""
    base = _index(baseline)
    cand = _index(candidate)
    inconclusive = _candidate_has_failed_phase(candidate)

    new: List[Dict[str, Any]] = []
    resolved: List[Dict[str, Any]] = []
    regressed: List[Dict[str, Any]] = []
    improved: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []

    for fid in sorted(set(base) | set(cand)):
        b = base.get(fid)
        c = cand.get(fid)
        if b is None and c is not None:
            new.append(_ref(c))
            continue
        if c is None and b is not None:
            resolved.append(_ref(b))
            continue
        # persisting in both → classify by severity/validation movement
        sev_delta = _sev_rank(c.get("severity")) - _sev_rank(b.get("severity"))
        val_delta = _val_rank(c.get("validation_status")) - _val_rank(
            b.get("validation_status")
        )
        ref = _ref(c)
        ref["baseline_severity"] = _severity(b.get("severity"))
        if sev_delta > 0 or val_delta < 0:
            regressed.append(ref)
        elif sev_delta < 0 or val_delta > 0:
            improved.append(ref)
        else:
            unchanged.append(ref)

    project = str(candidate.get("project") or baseline.get("project") or "").strip()
    diff: Dict[str, Any] = {
        "project": project,
        "baseline_run_id": str(baseline.get("run_id") or "").strip(),
        "candidate_run_id": str(candidate.get("run_id") or "").strip(),
        "inconclusive": inconclusive,
        "new": new,
        "resolved": resolved,
        "regressed": regressed,
        "improved": improved,
        "unchanged": unchanged,
        "summary": {
            "new": len(new),
            "resolved": len(resolved),
            "regressed": len(regressed),
            "improved": len(improved),
            "unchanged": len(unchanged),
            "risk_regression": bool(regressed) or any(
                f["severity"] in {"critical", "high"} for f in new
            ),
        },
    }
    diff["gate"] = compare_gate(diff)
    return diff


def compare_summary(diff: Dict[str, Any]) -> Dict[str, Any]:
    """Return the summary counts of a compare payload."""
    summary = diff.get("summary")
    return dict(summary) if isinstance(summary, dict) else {}


def compare_gate(
    diff: Dict[str, Any],
    *,
    fail_on: Tuple[str, ...] = DEFAULT_GATE_FAIL_ON,
) -> Dict[str, Any]:
    """Deterministic release gate over a compare payload.

    A failed candidate phase is surfaced as an ``inconclusive`` reason but never
    fails the gate on its own (mirrors Scan Diff: a failed phase is not a
    regression). Supported tokens: ``regressed``, ``new_critical``, ``new_high``.
    """
    reasons: List[str] = []
    new = diff.get("new") or []
    regressed = diff.get("regressed") or []
    if "regressed" in fail_on and regressed:
        reasons.append(f"{len(regressed)} regressed finding(s)")
    if "new_critical" in fail_on and any(f.get("severity") == "critical" for f in new):
        reasons.append("new critical finding(s)")
    if "new_high" in fail_on and any(f.get("severity") == "high" for f in new):
        reasons.append("new high finding(s)")

    notes: List[str] = []
    if diff.get("inconclusive"):
        notes.append("inconclusive: candidate has a failed phase")
    return {"passed": not reasons, "reasons": reasons, "notes": notes}


def compare_stored(
    store: Any,
    baseline_run_id: str,
    candidate_run_id: str,
) -> Dict[str, Any]:
    """Compare two persisted runs resolved from an :class:`AuditRunStore`."""
    baseline = store.export_run(str(baseline_run_id))
    candidate = store.export_run(str(candidate_run_id))
    diff = compare_runs(baseline, candidate)
    return diff


def resolve_baseline_id(run: Dict[str, Any]) -> Optional[str]:
    """Baseline run id linked on a candidate run, if any."""
    value = str(run.get("baseline_run_id") or "").strip()
    return value or None
