"""core/mission_links.py
Mission Center link integrity (M11) — closes the M1 decision D4.

The M1 contract (:func:`core.pentest_mission.link_audit_run` /
:func:`~core.pentest_mission.link_finding`) is deliberately **pure**: it stores a
reference without touching any store. This module is the opt-in, store-aware
layer the *surfaces* use:

* ``link_audit_run_checked`` / ``link_finding_checked`` validate that the id
  actually exists (in ``AuditRunStore`` / ``FindingsStore``) before delegating to
  the pure linker — so a surface can refuse to attach a dangling reference.
* ``resolve_links`` reports which of a mission's existing links are still present
  vs. stale (the referenced run/finding was since deleted), so the tab can flag
  them. The mission report already tolerates stale links on read; this names them.

Pure ``pentest_mission`` stays untouched (no I/O), preserving the M1 invariant.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def _audit_store(store: Optional[Any]) -> Any:
    if store is not None:
        return store
    from core.audit_store import AuditRunStore
    return AuditRunStore()


def _findings_store(store: Optional[Any]) -> Any:
    if store is not None:
        return store
    from core.findings_store import FindingsStore
    return FindingsStore()


def link_audit_run_checked(mission: Dict[str, Any], run_id: str, *,
                           audit_store: Optional[Any] = None) -> Dict[str, Any]:
    """Link ``run_id`` only if it exists in the AuditRunStore, else ``ValueError``."""
    from core.pentest_mission import link_audit_run
    clean = str(run_id or "").strip()
    if not clean:
        raise ValueError("run_id is required")
    if _audit_store(audit_store).get_run(clean) is None:
        raise ValueError(f"audit run not found: {clean}")
    return link_audit_run(mission, clean)


def link_finding_checked(mission: Dict[str, Any], finding_id: str, *,
                         findings_store: Optional[Any] = None) -> Dict[str, Any]:
    """Link ``finding_id`` only if it exists in the FindingsStore, else ``ValueError``."""
    from core.pentest_mission import link_finding
    clean = str(finding_id or "").strip()
    if not clean:
        raise ValueError("finding_id is required")
    if _findings_store(findings_store).get(clean) is None:
        raise ValueError(f"finding not found: {clean}")
    return link_finding(mission, clean)


def resolve_links(mission: Dict[str, Any], *, audit_store: Optional[Any] = None,
                  findings_store: Optional[Any] = None) -> Dict[str, Any]:
    """Partition a mission's links into present vs. stale (deleted) references.

    Returns ``{present_runs, stale_runs, present_findings, stale_findings}``
    (each a list of ids). Stale ids are kept, never dropped — naming them is the
    point; cleanup stays an operator decision.
    """
    from core.pentest_mission import normalize_mission
    normalized = normalize_mission(mission)
    astore = _audit_store(audit_store)
    fstore = _findings_store(findings_store)

    present_runs, stale_runs = [], []
    for run_id in normalized["linked_audit_run_ids"]:
        (present_runs if astore.get_run(run_id) is not None else stale_runs).append(run_id)
    present_findings, stale_findings = [], []
    for finding_id in normalized["linked_finding_ids"]:
        (present_findings if fstore.get(finding_id) is not None
         else stale_findings).append(finding_id)
    return {"present_runs": present_runs, "stale_runs": stale_runs,
            "present_findings": present_findings, "stale_findings": stale_findings}
