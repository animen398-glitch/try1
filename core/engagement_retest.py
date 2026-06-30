"""core/engagement_retest.py
Engagement retest — close the loop on an engagement's findings.

A retest re-checks each finding linked to the engagement against its **current**
status in the FindingsStore, to see what's been remediated since it was raised:
``fixed`` (status FIXED), ``open`` (OPEN / IN_PROGRESS), ``accepted`` (IGNORED /
FALSE_POSITIVE — a risk-accept decision) or ``missing`` (the finding was deleted).
It is a derive-on-read *view* over the existing FindingsStore — no re-scan, no
second store, no writes — mirroring :mod:`core.engagement_report`.

``build_retest`` reads the store and returns a canonical dict; ``render_json`` /
``render_markdown`` are pure, deterministic renderers over it.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

_FIXED = {"FIXED"}
_ACCEPTED = {"IGNORED", "FALSE_POSITIVE"}


def _outcome(status: str) -> str:
    if status in _FIXED:
        return "fixed"
    if status in _ACCEPTED:
        return "accepted"
    return "open"


def build_retest(engagement: Dict[str, Any], *,
                 findings_store: Optional[Any] = None) -> Dict[str, Any]:
    """Assemble the retest view for ``engagement`` (reads the FindingsStore).

    Each linked finding is resolved to its current status → outcome; a deleted
    finding is recorded as ``missing`` (kept, never faked). Returns
    ``{engagement_id, client, project, findings, summary}``."""
    from core.engagement import normalize_engagement
    normalized = normalize_engagement(engagement)
    if findings_store is None:
        from core.findings_store import FindingsStore
        findings_store = FindingsStore()

    findings: List[Dict[str, Any]] = []
    for fid in normalized["linked_finding_ids"]:
        row = findings_store.get(fid)
        if not isinstance(row, dict):
            findings.append({"finding_id": fid, "missing": True,
                             "outcome": "missing", "title": "",
                             "severity": "", "status": ""})
            continue
        status = str(row.get("status") or "")
        findings.append({"finding_id": row.get("id", fid), "missing": False,
                         "outcome": _outcome(status),
                         "title": row.get("title", ""),
                         "severity": row.get("severity", ""), "status": status})

    summary = {
        "total": len(findings),
        "fixed": sum(1 for f in findings if f["outcome"] == "fixed"),
        "open": sum(1 for f in findings if f["outcome"] == "open"),
        "accepted": sum(1 for f in findings if f["outcome"] == "accepted"),
        "missing": sum(1 for f in findings if f["outcome"] == "missing"),
    }
    return {"engagement_id": normalized["engagement_id"],
            "client": normalized["client"], "project": normalized["project"],
            "findings": findings, "summary": summary}


def render_markdown(retest: Dict[str, Any]) -> str:
    s = retest.get("summary") or {}
    lines = [
        f"# Engagement Retest {retest.get('engagement_id', '')}",
        "",
        f"- Client: {retest.get('client', '')}",
        f"- Project: {retest.get('project', '')}",
        f"- Findings retested: {s.get('total', 0)}",
        f"- Fixed: {s.get('fixed', 0)} · Still open: {s.get('open', 0)} · "
        f"Accepted: {s.get('accepted', 0)} · Missing: {s.get('missing', 0)}",
        "",
        "| Outcome | Severity | Title | Status | Finding |",
        "|---|---|---|---|---|",
    ]
    for f in retest.get("findings") or []:
        lines.append(
            "| {outcome} | {severity} | {title} | {status} | {fid} |".format(
                outcome=f.get("outcome", ""),
                severity=str(f.get("severity", "")),
                title=str(f.get("title", "")).replace("|", "\\|"),
                status=str(f.get("status", "")),
                fid=str(f.get("finding_id", "")),
            ))
    if not (retest.get("findings") or []):
        lines.append("| — | — | No findings linked to this engagement | — | — |")
    return "\n".join(lines).rstrip() + "\n"


def render_json(retest: Dict[str, Any]) -> str:
    return json.dumps(retest, ensure_ascii=False, indent=2, sort_keys=True)
