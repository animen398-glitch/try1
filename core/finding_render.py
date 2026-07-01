"""core/finding_render.py — shared finding-table renderers for evidence-first reports.

Pure, deterministic presentation over already-shaped finding dicts (the client /
review rows produced by ``core.audit_report``). No data access, no I/O, no network.

Extracted to remove the duplicated table renderers that had grown identical in
``core.mission_report`` and ``core.engagement_report`` (both mirror the same
evidence-first layout). Keep this module presentation-only: callers assemble the
report envelope and interleave these tables.
"""

import html
from typing import Any, Dict, List

_MD_HEADER = (
    "| Severity | Title | Validation | Confidence | Evidence |\n"
    "|---|---|---|---:|---|"
)


def finding_refs(finding: Dict[str, Any]) -> str:
    """Comma-joined evidence refs, or ``-`` when there are none."""
    refs = finding.get("evidence_refs") or []
    return ", ".join(str(ref) for ref in refs) if refs else "-"


def finding_md_table(rows: List[Dict[str, Any]]) -> str:
    """Markdown table of findings (severity/title/validation/confidence/evidence)."""
    lines = [_MD_HEADER]
    for finding in rows:
        lines.append(
            "| {severity} | {title} | {status} | {confidence} | {evidence} |".format(
                severity=str(finding.get("severity", "")),
                title=str(finding.get("title", "")).replace("|", "\\|"),
                status=str(finding.get("validation_status", finding.get("status", ""))),
                confidence=str(finding.get("confidence", "")),
                evidence=finding_refs(finding).replace("|", "\\|"),
            )
        )
    return "\n".join(lines)


def finding_html_table(rows: List[Dict[str, Any]]) -> str:
    """HTML table of findings; every cell escaped. Empty rows → a ``None`` row."""
    body = []
    for finding in rows:
        body.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
            f"<td>{html.escape(str(finding.get('title', '')))}</td>"
            f"<td>{html.escape(str(finding.get('validation_status', finding.get('status', ''))))}</td>"
            f"<td>{html.escape(str(finding.get('confidence', '')))}</td>"
            f"<td>{html.escape(finding_refs(finding))}</td>"
            "</tr>"
        )
    if not body:
        body.append('<tr><td colspan="5">None</td></tr>')
    return (
        "<table><thead><tr><th>Severity</th><th>Title</th><th>Validation</th>"
        "<th>Confidence</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(body) + "</tbody></table>"
    )
