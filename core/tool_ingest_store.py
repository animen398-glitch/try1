"""core/tool_ingest_store.py
Gated ingestion of a tool run into the platform stores — the first store-writing
step of the tool layer.

:func:`ingest_tool_run` persists a **completed**, already-authorized
:class:`~core.tool_adapter.ToolRunResult`'s findings and assets into the existing
``FindingsStore`` / ``AssetStore`` via the canonical bridge DTOs
(:mod:`core.tool_ingest`). It is gated and idempotent:

* only ``status == "completed"`` writes; ``blocked`` / ``skipped`` / any other
  status is a no-op (authorization was already decided upstream by
  ``evaluate_tool_allowed_for_mission`` — this never runs a tool, opens a socket,
  or re-checks policy);
* ``FindingsStore.upsert`` and ``AssetStore.sync`` are idempotent by identity, so
  re-ingesting the same result never duplicates.

Reuses the existing stores (no second findings/asset store). No network, no new
dependencies.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.tool_adapter import ToolRunResult


def ingest_tool_run(
    result: ToolRunResult,
    project: str,
    scan_id: str,
    *,
    findings_store: Optional[Any] = None,
    asset_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """Persist a completed tool run's findings/assets into the stores (idempotent).

    Returns ``{status, written, findings, assets}``. A non-completed result writes
    nothing (``written`` False); a blank project is rejected.
    """
    if not isinstance(result, ToolRunResult):
        raise TypeError("result must be a ToolRunResult")
    clean_project = str(project or "").strip()
    if not clean_project:
        raise ValueError("project is required")

    if result.status != "completed":
        return {"status": result.status, "written": False,
                "findings": 0, "assets": 0}

    from core.tool_ingest import tool_result_to_assets, tool_result_to_findings
    findings = tool_result_to_findings(result)
    assets = tool_result_to_assets(result)

    if findings_store is None:
        from core.findings_store import FindingsStore
        findings_store = FindingsStore()
    if asset_store is None:
        from core.asset_store import AssetStore
        asset_store = AssetStore()

    for finding in findings:
        findings_store.upsert(clean_project, finding.to_store(), scan_id=scan_id)
    if assets:
        asset_store.sync(clean_project, scan_id, assets)

    return {"status": "completed", "written": True,
            "findings": len(findings), "assets": len(assets)}
