"""Client-safe audit report rendering.

Pure offline renderers over the canonical audit-run JSON. Reports are views, not
storage, and they never promote rejected or quality-failed findings into the
client-facing critical section.
"""

from __future__ import annotations

import html
import json
from hashlib import sha1
from typing import Any, Dict, Iterable, List

from core.audit_schema import validate_audit_payload
from core.audit_workflow import audit_run_to_json


def _findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = payload.get("findings") or []
    return [item for item in findings if isinstance(item, dict)]


def client_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Findings eligible for client-facing vulnerability claims."""
    rows = []
    for finding in _findings(payload):
        if finding.get("validation_status") == "rejected":
            continue
        if finding.get("quality_gate") != "passed":
            continue
        if finding.get("client_facing") is False:
            continue
        rows.append(finding)
    return sorted(rows, key=lambda f: (str(f.get("severity", "")), str(f.get("title", ""))))


def review_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Findings that need appendix/review, not client-facing critical claims."""
    client_ids = {str(f.get("finding_id") or f.get("id")) for f in client_findings(payload)}
    rows = []
    for finding in _findings(payload):
        fid = str(finding.get("finding_id") or finding.get("id"))
        if fid not in client_ids:
            rows.append(finding)
    return sorted(rows, key=lambda f: (str(f.get("validation_status", "")), str(f.get("title", ""))))


def audit_summary(payload: Dict[str, Any]) -> Dict[str, int]:
    summary = {
        "findings": len(_findings(payload)),
        "client_facing": len(client_findings(payload)),
        "review": len(review_findings(payload)),
        "verified": 0,
        "rejected": 0,
        "needs_review": 0,
        "quality_failed": 0,
    }
    for finding in _findings(payload):
        status = finding.get("validation_status")
        if status in summary:
            summary[status] += 1
        if finding.get("quality_gate") == "failed":
            summary["quality_failed"] += 1
    return summary


def _refs(finding: Dict[str, Any]) -> str:
    refs = finding.get("evidence_refs") or []
    return ", ".join(str(ref) for ref in refs) if refs else "-"


def _md_table(rows: Iterable[Dict[str, Any]]) -> str:
    lines = [
        "| Severity | Title | Validation | Confidence | Evidence |",
        "|---|---|---|---:|---|",
    ]
    for finding in rows:
        lines.append(
            "| {severity} | {title} | {status} | {confidence} | {evidence} |".format(
                severity=str(finding.get("severity", "")),
                title=str(finding.get("title", "")).replace("|", "\\|"),
                status=str(finding.get("validation_status", "")),
                confidence=str(finding.get("confidence", "")),
                evidence=_refs(finding).replace("|", "\\|"),
            )
        )
    return "\n".join(lines)


def render_markdown(run: Dict[str, Any]) -> str:
    payload = audit_run_to_json(run)
    validate_audit_payload(payload, "asa_audit_run")
    summary = audit_summary(payload)
    phases = payload.get("phases") or []
    lines = [
        f"# Audit Run {payload.get('run_id', '')}",
        "",
        f"- Project: {payload.get('project', '')}",
        f"- Profile: {payload.get('profile', '')}",
        f"- Status: {payload.get('status', '')}",
        f"- Findings: {summary['findings']}",
        f"- Client-facing: {summary['client_facing']}",
        f"- Review appendix: {summary['review']}",
        "",
        "## Phase Summary",
        "",
        "| Phase | Status |",
        "|---|---|",
    ]
    for phase in phases:
        lines.append(f"| {phase.get('name', '')} | {phase.get('status', '')} |")
    lines.extend(["", "## Client-Facing Findings", ""])
    client = client_findings(payload)
    lines.append(_md_table(client) if client else "No client-facing findings passed the gate.")
    lines.extend(["", "## Review Appendix", ""])
    review = review_findings(payload)
    lines.append(_md_table(review) if review else "No rejected or review-only findings.")
    return "\n".join(lines).rstrip() + "\n"


def render_html(run: Dict[str, Any]) -> str:
    markdown = render_markdown(run)
    # Small deterministic HTML view, generated from the same sections as Markdown
    # without depending on a Markdown package or external assets.
    payload = audit_run_to_json(run)
    summary = audit_summary(payload)

    def table(rows: List[Dict[str, Any]]) -> str:
        body = []
        for finding in rows:
            body.append(
                "<tr>"
                f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
                f"<td>{html.escape(str(finding.get('title', '')))}</td>"
                f"<td>{html.escape(str(finding.get('validation_status', '')))}</td>"
                f"<td>{html.escape(str(finding.get('confidence', '')))}</td>"
                f"<td>{html.escape(_refs(finding))}</td>"
                "</tr>"
            )
        if not body:
            body.append("<tr><td colspan=\"5\">None</td></tr>")
        return (
            "<table><thead><tr><th>Severity</th><th>Title</th><th>Validation</th>"
            "<th>Confidence</th><th>Evidence</th></tr></thead><tbody>"
            + "".join(body)
            + "</tbody></table>"
        )

    phases = "".join(
        "<tr>"
        f"<td>{html.escape(str(phase.get('name', '')))}</td>"
        f"<td>{html.escape(str(phase.get('status', '')))}</td>"
        "</tr>"
        for phase in payload.get("phases") or []
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>ASA Audit Run</title>"
        "<style>body{font-family:Arial,sans-serif;margin:24px}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}"
        "td,th{border:1px solid #bbb;padding:6px;text-align:left}"
        "th{background:#eee}</style></head><body>"
        f"<h1>Audit Run {html.escape(str(payload.get('run_id', '')))}</h1>"
        f"<p><b>Project:</b> {html.escape(str(payload.get('project', '')))}"
        f" · <b>Profile:</b> {html.escape(str(payload.get('profile', '')))}"
        f" · <b>Status:</b> {html.escape(str(payload.get('status', '')))}</p>"
        f"<p><b>Findings:</b> {summary['findings']} · "
        f"<b>Client-facing:</b> {summary['client_facing']} · "
        f"<b>Review appendix:</b> {summary['review']}</p>"
        "<h2>Phase Summary</h2>"
        "<table><thead><tr><th>Phase</th><th>Status</th></tr></thead>"
        f"<tbody>{phases}</tbody></table>"
        "<h2>Client-Facing Findings</h2>"
        f"{table(client_findings(payload))}"
        "<h2>Review Appendix</h2>"
        f"{table(review_findings(payload))}"
        f"<!-- markdown-sha={sha1(markdown.encode('utf-8')).hexdigest()} -->"
        "</body></html>"
    )


def render_json(run: Dict[str, Any]) -> str:
    payload = audit_run_to_json(run)
    validate_audit_payload(payload, "asa_audit_run")
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
