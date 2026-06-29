"""core/tool_pipeline.py
Offline tool-evidence pipeline — composes the Tool Adapter Contract (M3) and the
per-tool parsers into one store-free call.

``assemble_tool_run`` does three things, in order, and nothing else:

1. build the M3 :class:`~core.tool_adapter.ToolRunRequest` (binds the mission's
   id / project / target / profile / ROE);
2. gate the tool against the mission via
   :func:`~core.tool_adapter.evaluate_tool_allowed_for_mission` — a **blocked**
   tool returns a ``ToolRunResult`` with status ``"blocked"`` and no
   findings/assets, and the evidence is never parsed;
3. otherwise parse the already-captured ``evidence``
   (:func:`core.tool_parsers.parse_tool_output`) and normalize it into a
   ``ToolRunResult`` (:func:`~core.tool_adapter.map_tool_result_to_findings`). An
   allowed tool that has no parser yet yields status ``"skipped"``.

It does **not** execute a tool, open a socket, or write to a store — ``evidence``
is data the caller already captured offline. Pure / deterministic / no new deps.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.tool_adapter import (
    ToolRunResult,
    build_tool_request,
    evaluate_tool_allowed_for_mission,
    map_tool_result_to_findings,
)
from core.tool_parsers import has_parser, parse_tool_output


def _empty_result(request, status: str) -> ToolRunResult:
    return ToolRunResult(
        tool=request.tool,
        action=request.action,
        mission_id=request.mission_id,
        target=request.target,
        status=status,
        findings=[],
        assets=[],
        evidence_refs=[],
    )


def assemble_tool_run(
    mission: Dict[str, Any],
    tool: str,
    evidence: Optional[Dict[str, Any]] = None,
    *,
    target: Optional[str] = None,
) -> ToolRunResult:
    """Gate → (if allowed) parse captured ``evidence`` → normalize, as one
    store-free :class:`ToolRunResult`.

    ``blocked`` if the mission's policy/ROE denies the tool (never parses);
    ``skipped`` if allowed but no parser is registered for the tool;
    ``completed`` otherwise. Never runs a tool, opens a socket, or writes a store.
    """
    request = build_tool_request(mission, tool, target=target)
    decision = evaluate_tool_allowed_for_mission(mission, tool, target=request.target)
    if not decision.get("allowed"):
        return _empty_result(request, "blocked")
    if not has_parser(request.tool):
        return _empty_result(request, "skipped")
    parsed = parse_tool_output(request.tool, evidence or {})
    return map_tool_result_to_findings(request, parsed, status="completed")
