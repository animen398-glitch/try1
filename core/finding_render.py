"""core/finding_render.py — shared finding-table renderers for evidence-first reports.

Pure, deterministic presentation over already-shaped finding dicts (the client /
review rows produced by ``core.audit_report``). No data access, no I/O, no network.

Extracted to remove the duplicated table renderers that had grown identical in
``core.mission_report`` and ``core.engagement_report`` (both mirror the same
evidence-first layout). Keep this module presentation-only: callers assemble the
report envelope and interleave these tables.
"""

import html
from hashlib import sha1
from typing import Any, Dict, List

_MD_HEADER = (
    "| Severity | Title | Validation | Confidence | Evidence |\n"
    "|---|---|---|---:|---|"
)


def html_open(title: str) -> str:
    """Opening of a report HTML document (doctype/head/style) through ``<body>``.

    ``title`` is emitted verbatim (all callers pass static ASCII titles), keeping
    the extracted output byte-identical to the inlined envelopes it replaces.
    """
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>{title}</title>"
        "<style>body{font-family:Arial,sans-serif;margin:24px}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}"
        "td,th{border:1px solid #bbb;padding:6px;text-align:left}"
        "th{background:#eee}</style></head><body>"
    )


def html_close(markdown: str) -> str:
    """Closing of a report HTML document: the ``markdown-sha`` provenance comment
    (over the sibling markdown rendering) plus ``</body></html>``."""
    return (
        f"<!-- markdown-sha={sha1(markdown.encode('utf-8')).hexdigest()} -->"
        "</body></html>"
    )


def finding_refs(finding: Dict[str, Any]) -> str:
    """Comma-joined evidence refs, or ``-`` when there are none."""
    refs = finding.get("evidence_refs") or []
    return ", ".join(str(ref) for ref in refs) if refs else "-"


def finding_md_table(rows: List[Dict[str, Any]]) -> str:
    """Markdown table of findings (severity/title/validation/confidence/evidence).

    Rows are governed (E9): any raw secret embedded in a free-text cell is masked
    at this client-facing boundary. Normal rows are unchanged.
    """
    from core.data_governance import govern_rows

    lines = [_MD_HEADER]
    for finding in govern_rows(rows):
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
    """HTML table of findings; every cell escaped. Empty rows → a ``None`` row.

    Rows are governed (E9) so a raw secret in a free-text cell is masked before
    escaping/rendering.
    """
    from core.data_governance import govern_rows

    body = []
    for finding in govern_rows(rows):
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
