"""Client-safe audit report rendering.

Pure offline renderers over the canonical audit-run JSON. Reports are views, not
storage, and they never promote rejected or quality-failed findings into the
client-facing critical section.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, Iterable, List

from core.finding_render import html_close, html_open

from core.audit_schema import validate_audit_payload
from core.audit_workflow import audit_run_to_json
from core.coverage import (
    coverage_from_audit_run,
    render_coverage_html,
    render_coverage_markdown,
)


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


def _scenario_lines(payload: Dict[str, Any]) -> List[str]:
    """Additive scenario/context bullets, only for keys present on the run."""
    lines: List[str] = []
    if payload.get("template"):
        lines.append(f"- Scenario: {payload.get('template')}")
    if "auth_context" in payload:
        lines.append(f"- Authenticated context: {'yes' if payload.get('auth_context') else 'no'}")
    if payload.get("baseline_run_id"):
        lines.append(f"- Baseline run: {payload.get('baseline_run_id')}")
    roe = payload.get("roe")
    if isinstance(roe, dict) and roe:
        from core.audit_scope import roe_summary

        lines.append(f"- ROE: {roe_summary(roe)}")
    return lines


def _scenario_html(payload: Dict[str, Any]) -> str:
    lines = _scenario_lines(payload)
    if not lines:
        return ""
    items = "".join(f"<li>{html.escape(line[2:])}</li>" for line in lines)
    return f"<ul>{items}</ul>"


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
        *_scenario_lines(payload),
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
    lines.extend(["", render_coverage_markdown(coverage_from_audit_run(payload)).rstrip()])
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
        html_open("ASA Audit Run") +
        f"<h1>Audit Run {html.escape(str(payload.get('run_id', '')))}</h1>"
        f"<p><b>Project:</b> {html.escape(str(payload.get('project', '')))}"
        f" | <b>Profile:</b> {html.escape(str(payload.get('profile', '')))}"
        f" | <b>Status:</b> {html.escape(str(payload.get('status', '')))}</p>"
        f"{_scenario_html(payload)}"
        f"<p><b>Findings:</b> {summary['findings']} | "
        f"<b>Client-facing:</b> {summary['client_facing']} | "
        f"<b>Review appendix:</b> {summary['review']}</p>"
        "<h2>Phase Summary</h2>"
        "<table><thead><tr><th>Phase</th><th>Status</th></tr></thead>"
        f"<tbody>{phases}</tbody></table>"
        "<h2>Client-Facing Findings</h2>"
        f"{table(client_findings(payload))}"
        "<h2>Review Appendix</h2>"
        f"{table(review_findings(payload))}"
        + render_coverage_html(coverage_from_audit_run(payload))
        + html_close(markdown)
    )


def render_json(run: Dict[str, Any]) -> str:
    payload = audit_run_to_json(run)
    validate_audit_payload(payload, "asa_audit_run")
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


# --- A/B comparison surfaces (F5) — views over the same compare payload --------

_COMPARE_BUCKETS = ("new", "resolved", "regressed", "improved", "unchanged")


def _compare_rows(diff: Dict[str, Any], bucket: str) -> List[Dict[str, Any]]:
    rows = diff.get(bucket) or []
    return [item for item in rows if isinstance(item, dict)]


def _compare_md_table(rows: Iterable[Dict[str, Any]]) -> str:
    lines = [
        "| Finding | Severity | Baseline | Validation |",
        "|---|---|---|---|",
    ]
    for ref in rows:
        lines.append(
            "| {fid} | {sev} | {base} | {val} |".format(
                fid=str(ref.get("finding_id", "")).replace("|", "\\|"),
                sev=str(ref.get("severity", "")),
                base=str(ref.get("baseline_severity", "-")),
                val=str(ref.get("validation_status", "")),
            )
        )
    return "\n".join(lines)


def render_compare_markdown(diff: Dict[str, Any]) -> str:
    validate_audit_payload(diff, "asa_audit_compare")
    summary = diff.get("summary") or {}
    gate = diff.get("gate") or {}
    gate_state = "PASS" if gate.get("passed") else "FAIL"
    lines = [
        f"# Audit Compare {diff.get('candidate_run_id', '')} vs {diff.get('baseline_run_id', '')}",
        "",
        f"- Project: {diff.get('project', '')}",
        f"- Baseline run: {diff.get('baseline_run_id', '')}",
        f"- Candidate run: {diff.get('candidate_run_id', '')}",
        f"- Inconclusive: {'yes' if diff.get('inconclusive') else 'no'}",
        f"- Gate: {gate_state}",
    ]
    for reason in gate.get("reasons") or []:
        lines.append(f"  - reason: {reason}")
    for note in gate.get("notes") or []:
        lines.append(f"  - note: {note}")
    lines.extend(["", "## Summary", "", "| Bucket | Count |", "|---|---:|"])
    for bucket in _COMPARE_BUCKETS:
        lines.append(f"| {bucket} | {int(summary.get(bucket, 0))} |")
    for bucket in ("regressed", "new", "resolved"):
        rows = _compare_rows(diff, bucket)
        lines.extend(["", f"## {bucket.capitalize()}", ""])
        lines.append(_compare_md_table(rows) if rows else f"No {bucket} findings.")
    return "\n".join(lines).rstrip() + "\n"


def render_compare_html(diff: Dict[str, Any]) -> str:
    markdown = render_compare_markdown(diff)
    summary = diff.get("summary") or {}
    gate = diff.get("gate") or {}
    gate_state = "PASS" if gate.get("passed") else "FAIL"

    def table(rows: List[Dict[str, Any]]) -> str:
        body = []
        for ref in rows:
            body.append(
                "<tr>"
                f"<td>{html.escape(str(ref.get('finding_id', '')))}</td>"
                f"<td>{html.escape(str(ref.get('severity', '')))}</td>"
                f"<td>{html.escape(str(ref.get('baseline_severity', '-')))}</td>"
                f"<td>{html.escape(str(ref.get('validation_status', '')))}</td>"
                "</tr>"
            )
        if not body:
            body.append("<tr><td colspan=\"4\">None</td></tr>")
        return (
            "<table><thead><tr><th>Finding</th><th>Severity</th>"
            "<th>Baseline</th><th>Validation</th></tr></thead><tbody>"
            + "".join(body)
            + "</tbody></table>"
        )

    rows = "".join(
        f"<tr><td>{bucket}</td><td>{int(summary.get(bucket, 0))}</td></tr>"
        for bucket in _COMPARE_BUCKETS
    )
    sections = "".join(
        f"<h2>{bucket.capitalize()}</h2>{table(_compare_rows(diff, bucket))}"
        for bucket in ("regressed", "new", "resolved")
    )
    return (
        html_open("ASA Audit Compare") +
        f"<h1>Audit Compare {html.escape(str(diff.get('candidate_run_id', '')))}"
        f" vs {html.escape(str(diff.get('baseline_run_id', '')))}</h1>"
        f"<p><b>Project:</b> {html.escape(str(diff.get('project', '')))}"
        f" | <b>Inconclusive:</b> {'yes' if diff.get('inconclusive') else 'no'}"
        f" | <b>Gate:</b> {gate_state}</p>"
        "<h2>Summary</h2>"
        "<table><thead><tr><th>Bucket</th><th>Count</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        f"{sections}"
        + html_close(markdown)
    )


def render_compare_json(diff: Dict[str, Any]) -> str:
    validate_audit_payload(diff, "asa_audit_compare")
    return json.dumps(diff, ensure_ascii=False, indent=2, sort_keys=True)
