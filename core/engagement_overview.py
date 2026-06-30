"""core/engagement_overview.py
Engagement portfolio overview (derive-on-read).

A view over ``EngagementStore``: counts by status + a compact per-engagement row
(client / project / status / linked counts / updated). No second store, no new
state — mirrors :mod:`core.mission_overview`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.engagement import ENGAGEMENT_STATUSES


def build_engagement_overview(*, store: Optional[Any] = None,
                              project: Optional[str] = None) -> Dict[str, Any]:
    """Portfolio overview of engagements (optionally scoped to ``project``).

    Returns ``{total, counts:{status:n}, engagements:[row]}`` where each row is
    ``{engagement_id, client, project, status, missions, audit_runs, findings,
    updated_at}``."""
    if store is None:
        from core.engagement_store import EngagementStore
        store = EngagementStore()
    rows = store.list_engagements(project)
    counts: Dict[str, int] = {status: 0 for status in sorted(ENGAGEMENT_STATUSES)}
    out_rows: List[Dict[str, Any]] = []
    for e in rows:
        payload = e.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        status = str(e.get("status") or "")
        if status in counts:
            counts[status] += 1
        out_rows.append({
            "engagement_id": e.get("id"),
            "client": e.get("client") or payload.get("client"),
            "project": e.get("project"),
            "status": status,
            "missions": len(payload.get("linked_mission_ids") or []),
            "audit_runs": len(payload.get("linked_audit_run_ids") or []),
            "findings": len(payload.get("linked_finding_ids") or []),
            "updated_at": e.get("updated_at"),
        })
    return {"total": len(rows), "counts": counts, "engagements": out_rows}
