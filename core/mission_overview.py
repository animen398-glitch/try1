"""core/mission_overview.py
Mission Center portfolio overview (M7) — derive-on-read, no new state.

Aggregates the persisted missions into a portfolio view: counts by lifecycle
status, and per mission the outcome of its most recent linked Audit Run (status +
client-facing finding count, reusing :mod:`core.audit_report`). It is a *view*
over the existing stores (``MissionStore`` + ``AuditRunStore``), never a second
source — the same discipline as :mod:`core.mission_report`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _latest_run(run_ids: Optional[List[str]], audit_store: Any) -> Optional[Dict[str, Any]]:
    """The most-recently-updated linked run payload (or None), missing runs skipped."""
    latest: Optional[Dict[str, Any]] = None
    for run_id in run_ids or []:
        row = audit_store.get_run(run_id)
        payload = row.get("payload") if isinstance(row, dict) else None
        if not isinstance(payload, dict):
            continue
        if (latest is None
                or str(payload.get("updated_at") or payload.get("run_id") or "")
                >= str(latest.get("updated_at") or latest.get("run_id") or "")):
            latest = payload
    return latest


def mission_run_trend(
    mission: Dict[str, Any],
    *,
    audit_store: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Per-mission run history (M15): one row per linked audit run, ordered by
    time, with its client-facing finding count.

    Derive-on-read over the mission's ``linked_audit_run_ids`` resolved against the
    AuditRunStore (reusing :func:`core.audit_report.client_findings`). Missing runs
    are skipped, never faked. Returns ``[{run_id, at, status, client_facing}]``.
    """
    from core import audit_report
    from core.pentest_mission import normalize_mission

    if audit_store is None:
        from core.audit_store import AuditRunStore
        audit_store = AuditRunStore()

    normalized = normalize_mission(mission)
    rows: List[Dict[str, Any]] = []
    for run_id in normalized["linked_audit_run_ids"]:
        row = audit_store.get_run(run_id)
        payload = row.get("payload") if isinstance(row, dict) else None
        if not isinstance(payload, dict):
            continue
        rows.append({
            "run_id": payload.get("run_id", run_id),
            "at": payload.get("updated_at") or payload.get("created_at"),
            "status": payload.get("status", ""),
            "client_facing": len(audit_report.client_findings(payload)),
        })
    rows.sort(key=lambda row: str(row.get("at") or ""))
    return rows


def build_mission_overview(
    *,
    mission_store: Optional[Any] = None,
    audit_store: Optional[Any] = None,
    project: Optional[str] = None,
) -> Dict[str, Any]:
    """Portfolio summary of missions (optionally scoped to ``project``).

    Returns ``{total, counts: {status: n}, client_facing, missions: [row]}`` where
    each row carries the mission's last linked run outcome (status +
    client-facing finding count). Reads stores; pure aggregation otherwise.
    """
    from core import audit_report
    from core.pentest_mission import MISSION_STATUSES

    if mission_store is None:
        from core.mission_store import MissionStore
        mission_store = MissionStore()
    if audit_store is None:
        from core.audit_store import AuditRunStore
        audit_store = AuditRunStore()

    missions = mission_store.list_missions(project)
    counts: Dict[str, int] = {status: 0 for status in sorted(MISSION_STATUSES)}
    rows: List[Dict[str, Any]] = []
    total_client = 0
    for mission in missions:
        payload = mission.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        status = str(mission.get("status") or "")
        counts[status] = counts.get(status, 0) + 1
        last = _latest_run(payload.get("linked_audit_run_ids"), audit_store)
        client = len(audit_report.client_findings(last)) if last else 0
        total_client += client
        rows.append({
            "mission_id": mission.get("id"),
            "project": mission.get("project"),
            "objective": payload.get("objective"),
            "status": status,
            "updated_at": mission.get("updated_at"),
            "last_run_id": last.get("run_id") if last else None,
            "last_run_status": last.get("status") if last else None,
            "client_facing": client,
        })
    rows.sort(key=lambda row: str(row.get("updated_at") or ""), reverse=True)
    return {"total": len(missions), "counts": counts,
            "client_facing": total_client, "missions": rows}
