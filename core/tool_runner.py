"""core/tool_runner.py
End-to-end tool-run orchestrator — the capstone of the tool layer.

:func:`run_tool_for_mission` composes the two halves of the stack into one call:

1. :func:`core.tool_pipeline.assemble_tool_run` — gate the tool against the
   mission, then (if allowed) parse the already-captured ``evidence`` into a
   store-free :class:`~core.tool_adapter.ToolRunResult`;
2. :func:`core.tool_ingest_store.ingest_tool_run` — persist a **completed**
   result's findings/assets into the existing ``FindingsStore`` / ``AssetStore``
   (gated and idempotent).

This mirrors how :func:`core.mission_runner.run_mission` wraps
``audit_runner.build_audit_run`` + persist. It is pure composition: no new
detection or policy, no second store, no network, no new dependencies, and a
tool is still never executed (``evidence`` was captured offline upstream). A
``blocked`` or ``skipped`` run flows through unchanged — assemble marks the
status and the ingestion step is a no-op.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from core.tool_adapter import ToolRunResult
from core.tool_ingest_store import ingest_tool_run
from core.tool_pipeline import assemble_tool_run

# Synthetic scan-id prefix grouping a single tool run's ingested findings/assets.
# A tool run is not persisted as its own entity (no second store), so this is the
# only handle that ties the ingested items back to one run — the timeline derives
# a ``tool_run`` event from it on read.
_TOOL_SCAN_PREFIX = "tool-"


def tool_scan_id(tool: str, *, now: Optional[int] = None) -> str:
    """The synthetic ``scan_id`` for a tool run: ``tool-<tool>-<unix_ts>``.

    Single source of truth for the convention shared by the GUI / web run
    surfaces and parsed back by :func:`parse_tool_scan_id`.
    """
    ts = int(time.time()) if now is None else int(now)
    return f"{_TOOL_SCAN_PREFIX}{tool}-{ts}"


def parse_tool_scan_id(scan_id: Any) -> Optional[str]:
    """The tool name encoded in a :func:`tool_scan_id` value, or ``None``.

    Registry tool names use underscores (no hyphens), so the trailing
    ``-<unix_ts>`` is split off at the last hyphen.
    """
    text = str(scan_id or "")
    if not text.startswith(_TOOL_SCAN_PREFIX):
        return None
    rest = text[len(_TOOL_SCAN_PREFIX):]
    idx = rest.rfind("-")
    if idx <= 0:
        return None
    name, ts = rest[:idx], rest[idx + 1:]
    if not name or not ts.isdigit():
        return None
    return name


def run_tool_for_mission(
    mission: Dict[str, Any],
    tool: Any,
    evidence: Optional[Dict[str, Any]] = None,
    *,
    scan_id: str,
    project: Optional[str] = None,
    target: Optional[str] = None,
    findings_store: Optional[Any] = None,
    asset_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """Gate → parse captured ``evidence`` → ingest, as one mission-scoped call.

    ``project`` defaults to the mission's own ``project``. Returns
    ``{"result": ToolRunResult, "ingest": {status, written, findings, assets}}``:
    the result is the store-free run (render it via :mod:`core.tool_report`), the
    ingest summary reports what was persisted. A ``blocked`` / ``skipped`` result
    persists nothing (``ingest['written']`` is False). Never runs a tool, opens a
    socket, or re-checks policy.
    """
    result: ToolRunResult = assemble_tool_run(
        mission, tool, evidence, target=target)
    clean_project = str(
        project or (mission or {}).get("project") or "").strip()
    ingest = ingest_tool_run(
        result, clean_project, scan_id,
        findings_store=findings_store, asset_store=asset_store)
    return {"result": result, "ingest": ingest}
