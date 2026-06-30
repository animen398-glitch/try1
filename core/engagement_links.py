"""core/engagement_links.py
Engagement link integrity (F3) — the store-aware layer over the pure contract.

The F1 contract (:func:`core.engagement.link_mission` /
:func:`~core.engagement.link_audit_run` / :func:`~core.engagement.link_finding`)
is deliberately **pure**: it stores a reference without touching any store. This
module is the opt-in, store-aware layer the surfaces use (mirrors
:mod:`core.mission_links`):

* ``link_*_checked`` validate that the id actually exists (in ``MissionStore`` /
  ``AuditRunStore`` / ``FindingsStore``) before delegating to the pure linker — so
  a surface can refuse to attach a dangling reference.
* ``resolve_links`` reports which of an engagement's existing links are still
  present vs. stale (the referenced object was since deleted), so a surface can
  flag them; stale ids are named, never silently dropped.
* ``prune_stale_links`` is the operator-driven cleanup that drops only the stale
  ids via a pure rebuild.

Pure ``core.engagement`` stays untouched (no I/O), preserving the F1 invariant.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def _mission_store(store: Optional[Any]) -> Any:
    if store is not None:
        return store
    from core.mission_store import MissionStore
    return MissionStore()


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


def link_mission_checked(engagement: Dict[str, Any], mission_id: str, *,
                         mission_store: Optional[Any] = None) -> Dict[str, Any]:
    """Link ``mission_id`` only if it exists in the MissionStore, else ``ValueError``."""
    from core.engagement import link_mission
    clean = str(mission_id or "").strip()
    if not clean:
        raise ValueError("mission_id is required")
    if _mission_store(mission_store).get_mission(clean) is None:
        raise ValueError(f"mission not found: {clean}")
    return link_mission(engagement, clean)


def link_audit_run_checked(engagement: Dict[str, Any], run_id: str, *,
                           audit_store: Optional[Any] = None) -> Dict[str, Any]:
    """Link ``run_id`` only if it exists in the AuditRunStore, else ``ValueError``."""
    from core.engagement import link_audit_run
    clean = str(run_id or "").strip()
    if not clean:
        raise ValueError("run_id is required")
    if _audit_store(audit_store).get_run(clean) is None:
        raise ValueError(f"audit run not found: {clean}")
    return link_audit_run(engagement, clean)


def link_finding_checked(engagement: Dict[str, Any], finding_id: str, *,
                         findings_store: Optional[Any] = None) -> Dict[str, Any]:
    """Link ``finding_id`` only if it exists in the FindingsStore, else ``ValueError``."""
    from core.engagement import link_finding
    clean = str(finding_id or "").strip()
    if not clean:
        raise ValueError("finding_id is required")
    if _findings_store(findings_store).get(clean) is None:
        raise ValueError(f"finding not found: {clean}")
    return link_finding(engagement, clean)


def resolve_links(engagement: Dict[str, Any], *,
                  mission_store: Optional[Any] = None,
                  audit_store: Optional[Any] = None,
                  findings_store: Optional[Any] = None) -> Dict[str, Any]:
    """Partition an engagement's links into present vs. stale (deleted) references.

    Returns ``{present_missions, stale_missions, present_runs, stale_runs,
    present_findings, stale_findings}`` (each a list of ids). Stale ids are kept,
    never dropped — naming them is the point; cleanup stays an operator decision.
    """
    from core.engagement import normalize_engagement
    normalized = normalize_engagement(engagement)
    mstore = _mission_store(mission_store)
    astore = _audit_store(audit_store)
    fstore = _findings_store(findings_store)

    present_missions, stale_missions = [], []
    for mid in normalized["linked_mission_ids"]:
        (present_missions if mstore.get_mission(mid) is not None
         else stale_missions).append(mid)
    present_runs, stale_runs = [], []
    for rid in normalized["linked_audit_run_ids"]:
        (present_runs if astore.get_run(rid) is not None
         else stale_runs).append(rid)
    present_findings, stale_findings = [], []
    for fid in normalized["linked_finding_ids"]:
        (present_findings if fstore.get(fid) is not None
         else stale_findings).append(fid)
    return {"present_missions": present_missions, "stale_missions": stale_missions,
            "present_runs": present_runs, "stale_runs": stale_runs,
            "present_findings": present_findings, "stale_findings": stale_findings}


def prune_stale_links(engagement: Dict[str, Any], *,
                      mission_store: Optional[Any] = None,
                      audit_store: Optional[Any] = None,
                      findings_store: Optional[Any] = None) -> Dict[str, Any]:
    """Return a new engagement keeping only links whose object still exists.

    Operator-driven cleanup: drops the ids :func:`resolve_links` flags as stale,
    leaving the present links untouched. Pure rebuild via
    :func:`core.engagement.normalize_engagement` — never mutates the input, and
    empty-safe (an engagement with no stale links comes back unchanged). Returns
    ``{engagement, removed_missions, removed_runs, removed_findings}``.
    """
    from core.engagement import normalize_engagement
    resolved = resolve_links(engagement, mission_store=mission_store,
                             audit_store=audit_store, findings_store=findings_store)
    pruned = dict(normalize_engagement(engagement))
    pruned["linked_mission_ids"] = list(resolved["present_missions"])
    pruned["linked_audit_run_ids"] = list(resolved["present_runs"])
    pruned["linked_finding_ids"] = list(resolved["present_findings"])
    return {"engagement": normalize_engagement(pruned),
            "removed_missions": resolved["stale_missions"],
            "removed_runs": resolved["stale_runs"],
            "removed_findings": resolved["stale_findings"]}
