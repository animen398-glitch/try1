"""core/engagement_report.py
Engagement report (F4) — the client-facing, evidence-first deliverable.

An engagement's report aggregates its envelope (client / project / scope / ROE /
authorization / status) with the work it ties together: the linked missions
(envelope summaries), the linked Audit Runs (their client-facing + review
findings, reused verbatim from :mod:`core.audit_report`), and an appendix of the
findings linked directly to the engagement. It is a *view*, not storage —
assembled on read from the existing stores, never a second source — and it
tolerates stale links (a deleted mission/run/finding is recorded, never faked),
exactly like :mod:`core.mission_report`.

``build_engagement_report`` reads the stores and returns a canonical dict;
``render_json`` / ``render_markdown`` / ``render_html`` are pure, deterministic
renderers over that dict.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List, Optional

from core.finding_render import finding_html_table, finding_md_table, html_close, html_open


def build_engagement_report(
    engagement: Dict[str, Any],
    *,
    mission_store: Optional[Any] = None,
    audit_store: Optional[Any] = None,
    findings_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """Assemble the evidence-first report dict for ``engagement`` (reads stores).

    Linked missions are resolved from the MissionStore (envelope summary; a
    missing one is a stub). Linked audit runs contribute their client-facing +
    review findings via :mod:`core.audit_report`. Linked findings are resolved
    from the FindingsStore. Missing references are flagged, never faked.
    """
    from core import audit_report
    from core.engagement import normalize_engagement

    normalized = normalize_engagement(engagement)
    if mission_store is None:
        from core.mission_store import MissionStore
        mission_store = MissionStore()
    if audit_store is None:
        from core.audit_store import AuditRunStore
        audit_store = AuditRunStore()
    if findings_store is None:
        from core.findings_store import FindingsStore
        findings_store = FindingsStore()

    missions: List[Dict[str, Any]] = []
    for mid in normalized["linked_mission_ids"]:
        row = mission_store.get_mission(mid)
        payload = row.get("payload") if isinstance(row, dict) else None
        if not isinstance(payload, dict):
            missions.append({"mission_id": mid, "missing": True,
                             "objective": "", "status": ""})
            continue
        missions.append({
            "mission_id": payload.get("mission_id", mid),
            "objective": payload.get("objective", ""),
            "status": payload.get("status", ""),
            "missing": False,
            "linked_runs": len(payload.get("linked_audit_run_ids") or []),
            "linked_findings": len(payload.get("linked_finding_ids") or []),
        })

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
        "linked_missions": len(normalized["linked_mission_ids"]),
        "missions_present": sum(1 for m in missions if not m["missing"]),
        "linked_runs": len(normalized["linked_audit_run_ids"]),
        "runs_present": sum(1 for run in runs if not run["missing"]),
        "client_facing": sum(len(run["client_findings"]) for run in runs),
        "review": sum(len(run["review_findings"]) for run in runs),
        "linked_findings": len(normalized["linked_finding_ids"]),
    }
    return {"engagement": normalized, "missions": missions, "runs": runs,
            "linked_findings": linked_findings, "summary": summary}


# ── pure renderers ────────────────────────────────────────────────────────────

def render_markdown(report: Dict[str, Any]) -> str:
    eng = report.get("engagement") or {}
    summary = report.get("summary") or {}
    scope = eng.get("scope") or {}
    roe = eng.get("roe") or {}
    auth = eng.get("authorization") or {}
    lines = [
        f"# Engagement Report {eng.get('engagement_id', '')}",
        "",
        f"- Client: {eng.get('client', '')}",
        f"- Project: {eng.get('project', '')}",
        f"- Profile: {eng.get('profile', '')}",
        f"- Status: {eng.get('status', '')}",
        f"- Report orientation: {eng.get('report_orientation', '')}",
        f"- Authorization: {'accepted' if auth.get('accepted') else 'NOT accepted'}"
        f" (by {auth.get('authorized_by') or '-'}, ref {auth.get('reference') or '-'})",
        f"- Scope: domains {', '.join(scope.get('allowed_domains') or []) or '-'}"
        f"; ips {', '.join(scope.get('allowed_ips') or []) or '-'}",
        f"- ROE: {'passive-only' if roe.get('passive_only') else 'active allowed'}"
        f"; rate {roe.get('rate_limit') or '-'}; window {roe.get('window') or '-'}",
        f"- Linked missions: {summary.get('linked_missions', 0)} "
        f"(present {summary.get('missions_present', 0)})",
        f"- Linked runs: {summary.get('linked_runs', 0)} "
        f"(present {summary.get('runs_present', 0)})",
        f"- Client-facing findings: {summary.get('client_facing', 0)}",
        f"- Review appendix: {summary.get('review', 0)}",
        f"- Linked findings: {summary.get('linked_findings', 0)}",
        "",
        "## Missions",
        "",
    ]
    missions = report.get("missions") or []
    if not missions:
        lines.append("No missions linked to this engagement.")
    for m in missions:
        if m.get("missing"):
            lines.append(f"- _{m.get('mission_id', '')} — not found (stale link)_")
        else:
            lines.append(
                f"- {m.get('mission_id', '')} — {m.get('objective', '')} "
                f"[{m.get('status', '')}] "
                f"(runs {m.get('linked_runs', 0)}, findings {m.get('linked_findings', 0)})")
    lines.extend(["", "## Linked Audit Runs", ""])
    runs = report.get("runs") or []
    if not runs:
        lines.append("No audit runs linked to this engagement.")
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
        lines.append("No findings explicitly linked to this engagement.")
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
    eng = report.get("engagement") or {}
    summary = report.get("summary") or {}
    auth = eng.get("authorization") or {}

    table = finding_html_table

    mission_items = []
    for m in report.get("missions") or []:
        if m.get("missing"):
            mission_items.append(
                f"<li><i>{html.escape(str(m.get('mission_id', '')))} — "
                "not found (stale link)</i></li>")
        else:
            mission_items.append(
                f"<li>{html.escape(str(m.get('mission_id', '')))} — "
                f"{html.escape(str(m.get('objective', '')))} "
                f"[{html.escape(str(m.get('status', '')))}]</li>")
    if not mission_items:
        mission_items.append("<li>No missions linked to this engagement.</li>")

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
        run_sections.append("<p>No audit runs linked to this engagement.</p>")

    present = [f for f in (report.get("linked_findings") or []) if not f.get("missing")]
    return (
        html_open("ASA Engagement Report") +
        f"<h1>Engagement Report {html.escape(str(eng.get('engagement_id', '')))}</h1>"
        f"<p><b>Client:</b> {html.escape(str(eng.get('client', '')))}"
        f" | <b>Project:</b> {html.escape(str(eng.get('project', '')))}"
        f" | <b>Status:</b> {html.escape(str(eng.get('status', '')))}</p>"
        f"<p><b>Authorization:</b> {'accepted' if auth.get('accepted') else 'NOT accepted'}"
        f" (by {html.escape(str(auth.get('authorized_by') or '-'))})</p>"
        f"<p><b>Linked missions:</b> {summary.get('linked_missions', 0)} "
        f"(present {summary.get('missions_present', 0)}) | "
        f"<b>Linked runs:</b> {summary.get('linked_runs', 0)} "
        f"(present {summary.get('runs_present', 0)}) | "
        f"<b>Client-facing:</b> {summary.get('client_facing', 0)} | "
        f"<b>Review:</b> {summary.get('review', 0)} | "
        f"<b>Linked findings:</b> {summary.get('linked_findings', 0)}</p>"
        "<h2>Missions</h2><ul>" + "".join(mission_items) + "</ul>"
        "<h2>Linked Audit Runs</h2>"
        + "".join(run_sections)
        + "<h2>Linked Findings (appendix)</h2>"
        + table(present)
        + html_close(markdown)
    )


def render_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
