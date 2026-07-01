"""core/mission_report.py
Mission Center report (M5) — the operator's evidence-first takeaway.

A mission's report aggregates its envelope (objective / ROE / allowed actions /
status) with the evidence it produced: the linked Audit Runs (their client-facing
and review findings, reused verbatim from :mod:`core.audit_report`) plus an
appendix of the findings explicitly linked to the mission. It is a *view*, not
storage — assembled on read from the existing stores, never a second source.

``build_mission_report`` reads the stores and returns a canonical report dict;
``render_json`` / ``render_markdown`` / ``render_html`` are pure, deterministic
renderers over that dict (mirroring :mod:`core.audit_report`).
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List, Optional

from core.finding_render import finding_html_table, finding_md_table, html_close, html_open


def build_mission_report(
    mission: Dict[str, Any],
    *,
    audit_store: Optional[Any] = None,
    findings_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """Assemble the evidence-first report dict for ``mission`` (reads stores).

    Each linked audit run contributes its client-facing + review findings (via
    :mod:`core.audit_report`); a missing run is recorded, never faked. Each
    linked finding id is resolved from the FindingsStore; a missing one is kept
    as a stub so the report is honest about stale links.
    """
    from core import audit_report
    from core.pentest_mission import normalize_mission

    normalized = normalize_mission(mission)
    if audit_store is None:
        from core.audit_store import AuditRunStore
        audit_store = AuditRunStore()
    if findings_store is None:
        from core.findings_store import FindingsStore
        findings_store = FindingsStore()

    runs: List[Dict[str, Any]] = []
    for run_id in normalized["linked_audit_run_ids"]:
        row = audit_store.get_run(run_id)
        payload = row.get("payload") if isinstance(row, dict) else None
        if not isinstance(payload, dict):
            runs.append({"run_id": run_id, "missing": True, "status": "",
                         "client_findings": [], "review_findings": [],
                         "summary": {}})
            continue
        runs.append({
            "run_id": payload.get("run_id", run_id),
            "status": payload.get("status", ""),
            "missing": False,
            "client_findings": audit_report.client_findings(payload),
            "review_findings": audit_report.review_findings(payload),
            "summary": audit_report.audit_summary(payload),
        })

    linked_findings: List[Dict[str, Any]] = []
    for fid in normalized["linked_finding_ids"]:
        row = findings_store.get(fid)
        linked_findings.append(row if isinstance(row, dict)
                               else {"id": fid, "missing": True})

    summary = {
        "linked_runs": len(normalized["linked_audit_run_ids"]),
        "runs_present": sum(1 for run in runs if not run["missing"]),
        "client_facing": sum(len(run["client_findings"]) for run in runs),
        "review": sum(len(run["review_findings"]) for run in runs),
        "linked_findings": len(normalized["linked_finding_ids"]),
    }
    return {"mission": normalized, "runs": runs,
            "linked_findings": linked_findings, "summary": summary}


# ── pure renderers ────────────────────────────────────────────────────────────

def _roe_line(mission: Dict[str, Any]) -> Optional[str]:
    roe = mission.get("roe")
    if isinstance(roe, dict) and roe:
        from core.audit_scope import roe_summary
        return f"- ROE: {roe_summary(roe)}"
    return None


def render_markdown(report: Dict[str, Any]) -> str:
    mission = report.get("mission") or {}
    summary = report.get("summary") or {}
    lines = [
        f"# Mission Report {mission.get('mission_id', '')}",
        "",
        f"- Objective: {mission.get('objective', '')}",
        f"- Project: {mission.get('project', '')}",
        f"- Profile: {mission.get('profile', '')}",
        f"- Status: {mission.get('status', '')}",
        f"- Report orientation: {mission.get('report_orientation', '')}",
    ]
    if mission.get("template"):
        lines.append(f"- Scenario: {mission.get('template')}")
    roe_line = _roe_line(mission)
    if roe_line:
        lines.append(roe_line)
    lines.extend([
        f"- Allowed actions: {', '.join(mission.get('allowed_actions') or []) or '-'}",
        f"- Linked runs: {summary.get('linked_runs', 0)} "
        f"(present {summary.get('runs_present', 0)})",
        f"- Client-facing findings: {summary.get('client_facing', 0)}",
        f"- Review appendix: {summary.get('review', 0)}",
        f"- Linked findings: {summary.get('linked_findings', 0)}",
        "",
        "## Linked Audit Runs",
        "",
    ])
    runs = report.get("runs") or []
    if not runs:
        lines.append("No audit runs linked to this mission.")
    for run in runs:
        lines.append(f"### Run {run.get('run_id', '')} ({run.get('status', '')})")
        lines.append("")
        if run.get("missing"):
            lines.append("_Run not found in the audit store (stale link)._")
            lines.append("")
            continue
        lines.append("**Client-facing findings**")
        lines.append("")
        client = run.get("client_findings") or []
        lines.append(finding_md_table(client) if client
                     else "No client-facing findings passed the gate.")
        lines.append("")
        lines.append("**Review appendix**")
        lines.append("")
        review = run.get("review_findings") or []
        lines.append(finding_md_table(review) if review
                     else "No rejected or review-only findings.")
        lines.append("")
    lines.extend(["## Linked Findings (appendix)", ""])
    linked = report.get("linked_findings") or []
    if not linked:
        lines.append("No findings explicitly linked to this mission.")
    else:
        present = [f for f in linked if not f.get("missing")]
        stale = [f for f in linked if f.get("missing")]
        lines.append(finding_md_table(present) if present
                     else "No resolvable linked findings.")
        for stub in stale:
            lines.append("")
            lines.append(f"_Linked finding not found (stale link): {stub.get('id', '')}_")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: Dict[str, Any]) -> str:
    markdown = render_markdown(report)
    mission = report.get("mission") or {}
    summary = report.get("summary") or {}

    table = finding_html_table

    run_sections = []
    for run in report.get("runs") or []:
        head = (f"<h3>Run {html.escape(str(run.get('run_id', '')))} "
                f"({html.escape(str(run.get('status', '')))})</h3>")
        if run.get("missing"):
            run_sections.append(head + "<p><i>Run not found (stale link).</i></p>")
            continue
        run_sections.append(
            head
            + "<h4>Client-facing findings</h4>" + table(run.get("client_findings") or [])
            + "<h4>Review appendix</h4>" + table(run.get("review_findings") or [])
        )
    if not run_sections:
        run_sections.append("<p>No audit runs linked to this mission.</p>")

    present = [f for f in (report.get("linked_findings") or []) if not f.get("missing")]
    roe_line = _roe_line(mission)
    return (
        html_open("ASA Mission Report") +
        f"<h1>Mission Report {html.escape(str(mission.get('mission_id', '')))}</h1>"
        f"<p><b>Objective:</b> {html.escape(str(mission.get('objective', '')))}</p>"
        f"<p><b>Project:</b> {html.escape(str(mission.get('project', '')))}"
        f" | <b>Profile:</b> {html.escape(str(mission.get('profile', '')))}"
        f" | <b>Status:</b> {html.escape(str(mission.get('status', '')))}</p>"
        + (f"<p>{html.escape(roe_line[2:])}</p>" if roe_line else "")
        + f"<p><b>Linked runs:</b> {summary.get('linked_runs', 0)} "
        f"(present {summary.get('runs_present', 0)}) | "
        f"<b>Client-facing:</b> {summary.get('client_facing', 0)} | "
        f"<b>Review:</b> {summary.get('review', 0)} | "
        f"<b>Linked findings:</b> {summary.get('linked_findings', 0)}</p>"
        "<h2>Linked Audit Runs</h2>"
        + "".join(run_sections)
        + "<h2>Linked Findings (appendix)</h2>"
        + table(present)
        + html_close(markdown)
    )


def render_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
