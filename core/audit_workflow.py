"""Client-safe audit run workflow contract.

Pure, deterministic helpers for the Authorized Pentest Workbench roadmap. This
module stores no state and intentionally does not write to FindingsStore; it
only shapes an audit-run payload that other surfaces can persist or export.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha1
from typing import Any, Dict, Iterable, List, Optional


AUDIT_PHASES = (
    "recon_snapshot",
    "finding_hunt",
    "validation",
    "risk_business_impact",
    "structured_output",
    "independent_verification",
)

AUDIT_STATUSES = {"pending", "running", "completed", "failed"}
PHASE_STATUSES = {"pending", "running", "completed", "failed", "skipped"}


def _stable_id(project: str, phases: Iterable[str]) -> str:
    raw = f"{project}|{'|'.join(phases)}"
    return f"audit-{sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _validate_phases(phases: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for phase in phases:
        name = str(phase or "").strip()
        if name not in AUDIT_PHASES:
            raise ValueError(f"unknown audit phase: {name}")
        if name not in seen:
            seen.add(name)
            out.append(name)
    if not out:
        raise ValueError("at least one audit phase is required")
    return out


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    if isinstance(value, tuple):
        return [_canonical(v) for v in value]
    return value


def create_audit_run(
    project: str,
    phases: Optional[List[str]] = None,
    *,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a deterministic audit-run payload."""
    clean_project = str(project or "").strip()
    if not clean_project:
        raise ValueError("project is required")
    phase_names = _validate_phases(phases or list(AUDIT_PHASES))
    clean_run_id = str(run_id or "").strip() or _stable_id(clean_project, phase_names)
    return {
        "run_id": clean_run_id,
        "project": clean_project,
        "profile": "client_safe",
        "status": "pending",
        "phases": [
            {"name": name, "status": "pending", "result": None}
            for name in phase_names
        ],
        "findings": [],
        "events": [],
    }


def _phase_index(run: Dict[str, Any], phase: str) -> int:
    name = str(phase or "").strip()
    if name not in AUDIT_PHASES:
        raise ValueError(f"unknown audit phase: {name}")
    for idx, item in enumerate(run.get("phases") or []):
        if isinstance(item, dict) and item.get("name") == name:
            return idx
    raise KeyError(f"phase is not part of this audit run: {name}")


def _merge_findings(run: Dict[str, Any], result: Dict[str, Any]) -> None:
    incoming = result.get("validated_findings") or result.get("findings") or []
    if not isinstance(incoming, list):
        return
    by_id = {
        str(item.get("finding_id") or item.get("id")): item
        for item in run.get("findings", [])
        if isinstance(item, dict) and (item.get("finding_id") or item.get("id"))
    }
    for item in incoming:
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("finding_id") or item.get("id") or "").strip()
        if not finding_id:
            continue
        row = dict(item)
        row["finding_id"] = finding_id
        by_id[finding_id] = _canonical(row)
    run["findings"] = [by_id[key] for key in sorted(by_id)]


def _add_event_once(run: Dict[str, Any], event: Dict[str, Any]) -> None:
    events = run.setdefault("events", [])
    canonical = _canonical(event)
    if canonical not in events:
        events.append(canonical)
    events.sort(key=lambda item: (item.get("phase", ""), item.get("type", "")))


def advance_audit_phase(
    run: Dict[str, Any],
    phase: str,
    result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a new run payload with one phase completed.

    Re-applying the same phase result is idempotent, so additive runs are stable
    and duplicate UI actions do not create duplicate audit events.
    """
    updated = deepcopy(run)
    idx = _phase_index(updated, phase)
    clean_result = _canonical(result or {})
    updated["phases"][idx]["status"] = "completed"
    updated["phases"][idx]["result"] = clean_result
    _merge_findings(updated, clean_result)
    _add_event_once(
        updated,
        {
            "type": "phase_completed",
            "phase": updated["phases"][idx]["name"],
            "run_id": updated.get("run_id"),
        },
    )
    phase_statuses = [item.get("status") for item in updated.get("phases", [])]
    if any(status == "failed" for status in phase_statuses):
        updated["status"] = "failed"
    elif all(status in {"completed", "skipped"} for status in phase_statuses):
        updated["status"] = "completed"
    else:
        updated["status"] = "running"
    return audit_run_to_json(updated)


def audit_run_to_json(run: Dict[str, Any]) -> Dict[str, Any]:
    """Canonical JSON-serializable audit-run export."""
    payload = _canonical(deepcopy(run))
    status = payload.get("status")
    if status not in AUDIT_STATUSES:
        raise ValueError(f"unknown audit run status: {status}")
    for phase in payload.get("phases") or []:
        if not isinstance(phase, dict):
            raise ValueError("phase entries must be objects")
        if phase.get("name") not in AUDIT_PHASES:
            raise ValueError(f"unknown audit phase: {phase.get('name')}")
        if phase.get("status") not in PHASE_STATUSES:
            raise ValueError(f"unknown phase status: {phase.get('status')}")
    return payload
