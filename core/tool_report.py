"""core/tool_report.py
Pure, offline report renderers for a tool run — the presentation layer above the
Tool Adapter Contract.

Renders a :class:`~core.tool_adapter.ToolRunResult` as deterministic JSON / MD /
HTML over its canonical, schema-shaped payload (``tool_result_to_json``). A view,
not storage: it reads an already-assembled result and produces a string. No store
writes, no network, no new dependencies — the same discipline as
:mod:`core.audit_report` / :mod:`core.mission_report`.
"""

from __future__ import annotations

import html
import json
from hashlib import sha1
from typing import Any, Dict, List

from core.tool_adapter import ToolRunResult, tool_result_to_json


def _payload(result: ToolRunResult) -> Dict[str, Any]:
    if not isinstance(result, ToolRunResult):
        raise TypeError("result must be a ToolRunResult")
    return tool_result_to_json(result)


def _esc_pipe(value: Any) -> str:
    return str(value or "").replace("|", "\\|")


def _refs(finding: Dict[str, Any]) -> str:
    refs = finding.get("evidence_refs") or []
    return ", ".join(str(ref) for ref in refs) if refs else "-"


def render_json(result: ToolRunResult) -> str:
    """Canonical, schema-shaped JSON export of a tool run (deterministic)."""
    return json.dumps(_payload(result), ensure_ascii=False, indent=2, sort_keys=True)


def _md_findings_table(findings: List[Dict[str, Any]]) -> str:
    lines = [
        "| Severity | Title | Asset | Location | Evidence |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            "| {sev} | {title} | {asset} | {loc} | {ev} |".format(
                sev=str(finding.get("severity", "")),
                title=_esc_pipe(finding.get("title")),
                asset=_esc_pipe(finding.get("asset")),
                loc=_esc_pipe(finding.get("location")),
                ev=_esc_pipe(_refs(finding)),
            )
        )
    return "\n".join(lines)


def _md_assets_table(assets: List[Dict[str, Any]]) -> str:
    lines = ["| Type | Value | Source |", "|---|---|---|"]
    for asset in assets:
        lines.append(
            "| {atype} | {value} | {source} |".format(
                atype=str(asset.get("asset_type", "")),
                value=_esc_pipe(asset.get("value")),
                source=str(asset.get("source", "")),
            )
        )
    return "\n".join(lines)


def render_markdown(result: ToolRunResult) -> str:
    payload = _payload(result)
    findings = payload.get("findings") or []
    assets = payload.get("assets") or []
    lines = [
        f"# Tool Run {payload.get('tool', '')}",
        "",
        f"- Action: {payload.get('action', '')}",
        f"- Mission: {payload.get('mission_id', '')}",
        f"- Target: {payload.get('target', '')}",
        f"- Status: {payload.get('status', '')}",
        f"- Findings: {len(findings)}",
        f"- Assets: {len(assets)}",
        "",
        "## Findings",
        "",
    ]
    lines.append(_md_findings_table(findings) if findings else "No findings.")
    lines.extend(["", "## Assets", ""])
    lines.append(_md_assets_table(assets) if assets else "No assets.")
    return "\n".join(lines).rstrip() + "\n"


def render_html(result: ToolRunResult) -> str:
    markdown = render_markdown(result)
    payload = _payload(result)
    findings = payload.get("findings") or []
    assets = payload.get("assets") or []

    def finding_rows() -> str:
        body = []
        for finding in findings:
            body.append(
                "<tr>"
                f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
                f"<td>{html.escape(str(finding.get('title', '')))}</td>"
                f"<td>{html.escape(str(finding.get('asset', '')))}</td>"
                f"<td>{html.escape(str(finding.get('location', '')))}</td>"
                f"<td>{html.escape(_refs(finding))}</td>"
                "</tr>"
            )
        if not body:
            body.append('<tr><td colspan="5">None</td></tr>')
        return (
            "<table><thead><tr><th>Severity</th><th>Title</th><th>Asset</th>"
            "<th>Location</th><th>Evidence</th></tr></thead><tbody>"
            + "".join(body) + "</tbody></table>"
        )

    def asset_rows() -> str:
        body = []
        for asset in assets:
            body.append(
                "<tr>"
                f"<td>{html.escape(str(asset.get('asset_type', '')))}</td>"
                f"<td>{html.escape(str(asset.get('value', '')))}</td>"
                f"<td>{html.escape(str(asset.get('source', '')))}</td>"
                "</tr>"
            )
        if not body:
            body.append('<tr><td colspan="3">None</td></tr>')
        return (
            "<table><thead><tr><th>Type</th><th>Value</th><th>Source</th>"
            "</tr></thead><tbody>" + "".join(body) + "</tbody></table>"
        )

    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>ASA Tool Run</title>"
        "<style>body{font-family:Arial,sans-serif;margin:24px}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}"
        "td,th{border:1px solid #bbb;padding:6px;text-align:left}"
        "th{background:#eee}</style></head><body>"
        f"<h1>Tool Run {html.escape(str(payload.get('tool', '')))}</h1>"
        f"<p><b>Action:</b> {html.escape(str(payload.get('action', '')))}"
        f" | <b>Mission:</b> {html.escape(str(payload.get('mission_id', '')))}"
        f" | <b>Target:</b> {html.escape(str(payload.get('target', '')))}"
        f" | <b>Status:</b> {html.escape(str(payload.get('status', '')))}</p>"
        f"<p><b>Findings:</b> {len(findings)} | <b>Assets:</b> {len(assets)}</p>"
        "<h2>Findings</h2>"
        f"{finding_rows()}"
        "<h2>Assets</h2>"
        f"{asset_rows()}"
        f"<!-- markdown-sha={sha1(markdown.encode('utf-8')).hexdigest()} -->"
        "</body></html>"
    )
