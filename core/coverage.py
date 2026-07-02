"""Coverage Gate & Capability Awareness (Roadmap E2).

Offline-first, dependency-free core layer that normalizes *what ran, what was
skipped or failed, and why* for a client-safe audit/scan. The point is
enterprise-grade honesty: a report should state its own coverage gaps rather
than silently omitting a phase that never executed.

Design notes
------------
- Pure and deterministic. No network, no filesystem writes, no new third-party
  dependencies. Optional-capability detection is delegated to
  :mod:`core.features` through an *injectable* predicate so tests stay offline.
- This module stores no state. Coverage is *derived* from an audit run, not
  persisted onto it, so it never changes the audit-run JSON contract/schema.
"""

from __future__ import annotations

import html
from typing import Any, Callable, Dict, List, Optional


# --- Normalized vocabulary ---------------------------------------------------

#: Coverage status for a single phase, and for the run overall.
COVERAGE_STATUSES = ("full", "partial", "skipped", "failed", "unavailable")

#: Exact compliance reason codes explaining a degraded coverage status.
COVERAGE_REASONS = (
    "missing_dependency",
    "scope_denied",
    "roe_denied",
    "failed_phase",
    "skipped_phase",
    "timeout",
    "quota",
    "auth_required",
    "passive_only",
)

#: Statuses that count as "the phase produced its intended coverage".
_COVERED = ("full",)
#: Statuses that count as degraded (ran partially or did not run).
_DEGRADED = ("partial", "skipped", "failed", "unavailable")

# How a legacy/modern audit-run phase status maps into coverage vocabulary.
_PHASE_STATUS_MAP = {
    "completed": ("full", None),
    "failed": ("failed", "failed_phase"),
    "skipped": ("skipped", "skipped_phase"),
    # A phase that never left pending/running did not deliver its coverage.
    "pending": ("partial", None),
    "running": ("partial", None),
}


def _clean(value: Any) -> str:
    return str(value if value is not None else "").strip()


def coverage_item(
    phase: str,
    status: str,
    reason: Optional[str] = None,
    detail: str = "",
) -> Dict[str, Any]:
    """Build one normalized coverage record.

    ``phase`` is a free-form phase/capability name. ``status`` must be one of
    :data:`COVERAGE_STATUSES`; ``reason`` (when given) must be one of
    :data:`COVERAGE_REASONS`. ``detail`` is optional human context.
    """
    clean_phase = _clean(phase)
    if not clean_phase:
        raise ValueError("coverage phase is required")
    clean_status = _clean(status)
    if clean_status not in COVERAGE_STATUSES:
        raise ValueError(f"unknown coverage status: {status!r}")
    clean_reason: Optional[str] = None
    if reason is not None and _clean(reason):
        clean_reason = _clean(reason)
        if clean_reason not in COVERAGE_REASONS:
            raise ValueError(f"unknown coverage reason: {reason!r}")
    return {
        "phase": clean_phase,
        "status": clean_status,
        "reason": clean_reason,
        "detail": _clean(detail),
    }


def _coerce_item(raw: Any) -> Optional[Dict[str, Any]]:
    """Best-effort normalize an arbitrary dict into a coverage item.

    Tolerates legacy/foreign shapes: an unknown status degrades to
    ``unavailable`` and an unknown reason is dropped rather than raising, so the
    adapter never fails a report render on dirty input.
    """
    if not isinstance(raw, dict):
        return None
    phase = _clean(raw.get("phase") or raw.get("name"))
    if not phase:
        return None
    status = _clean(raw.get("status"))
    if status not in COVERAGE_STATUSES:
        status = "unavailable"
    reason = raw.get("reason")
    reason = _clean(reason) if reason is not None else ""
    if reason and reason not in COVERAGE_REASONS:
        reason = ""
    detail = _clean(raw.get("detail"))
    return coverage_item(phase, status, reason or None, detail)


def build_coverage_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll a list of coverage items into a summary with an overall status.

    Overall status is deterministic:

    - no items                         -> ``unavailable``
    - every item ``full``              -> ``full``
    - some but not all ``full``        -> ``partial``
    - zero ``full`` and any ``failed`` -> ``failed``
    - zero ``full`` and any ``skipped``-> ``skipped``
    - otherwise                        -> ``unavailable``
    """
    clean_items: List[Dict[str, Any]] = []
    for raw in items or []:
        item = _coerce_item(raw)
        if item is not None:
            clean_items.append(item)

    counts = {status: 0 for status in COVERAGE_STATUSES}
    reasons: Dict[str, int] = {}
    for item in clean_items:
        counts[item["status"]] += 1
        if item["reason"]:
            reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1

    total = len(clean_items)
    covered = sum(counts[status] for status in _COVERED)
    degraded = sum(counts[status] for status in _DEGRADED)
    ratio = round(covered / total, 4) if total else 0.0

    if total == 0:
        overall = "unavailable"
    elif covered == total:
        overall = "full"
    elif covered > 0:
        overall = "partial"
    elif counts["failed"]:
        overall = "failed"
    elif counts["skipped"]:
        overall = "skipped"
    else:
        overall = "unavailable"

    return {
        "overall_status": overall,
        "total": total,
        "covered": covered,
        "degraded": degraded,
        "coverage_ratio": ratio,
        "counts": counts,
        "reasons": dict(sorted(reasons.items())),
        "items": clean_items,
    }


def coverage_for_dependency(
    phase: str,
    feature: str,
    *,
    available: Optional[Callable[[str], bool]] = None,
    detail: str = "",
) -> Dict[str, Any]:
    """Coverage for a phase gated on an optional capability.

    When the capability named ``feature`` (e.g. ``"playwright"`` or an external
    binary like ``"nuclei"``) is present the phase is ``full``; when it is
    absent the phase degrades to ``unavailable`` / ``missing_dependency``.

    ``available`` is an injectable predicate ``name -> bool`` (used by tests to
    simulate a missing dependency offline). When omitted, detection reuses
    :mod:`core.features` — its checks are local (``importlib``/``shutil.which``),
    never network calls.
    """
    predicate = available if available is not None else _default_available
    present = False
    try:
        present = bool(predicate(feature))
    except Exception:
        present = False
    if present:
        return coverage_item(phase, "full", None, detail)
    note = detail or f"optional capability '{feature}' not available"
    return coverage_item(phase, "unavailable", "missing_dependency", note)


def _default_available(feature: str) -> bool:
    """Resolve capability availability via :mod:`core.features` (offline)."""
    from core import features

    detector = getattr(features, f"has_{feature.replace('-', '_')}", None)
    if callable(detector):
        try:
            return bool(detector())
        except Exception:
            return False
    summary = features.summary()
    entry = summary.get(feature)
    return bool(entry and entry.get("available"))


def coverage_from_audit_run(run: Any) -> Dict[str, Any]:
    """Backward-compatible adapter: derive a coverage summary from an audit run.

    Accepts modern *and* legacy audit-run dicts. If the run already carries an
    explicit ``coverage`` block (either a summary dict with ``items`` or a bare
    list of items) it is normalized and reused; otherwise coverage is derived
    from the run's phase statuses. Malformed input never raises — the worst case
    is an empty, ``unavailable`` summary — so it cannot fail a report render or
    a schema-validation pass.
    """
    if not isinstance(run, dict):
        return build_coverage_summary([])

    explicit = run.get("coverage")
    if isinstance(explicit, dict) and isinstance(explicit.get("items"), list):
        return build_coverage_summary(explicit["items"])
    if isinstance(explicit, list):
        return build_coverage_summary(explicit)

    items: List[Dict[str, Any]] = []
    phases = run.get("phases")
    if isinstance(phases, list):
        for phase in phases:
            if not isinstance(phase, dict):
                continue
            name = _clean(phase.get("name"))
            if not name:
                continue
            raw_status = _clean(phase.get("status")).lower()
            status, reason = _PHASE_STATUS_MAP.get(raw_status, ("unavailable", None))
            detail = _phase_detail(phase)
            items.append(coverage_item(name, status, reason, detail))
    return build_coverage_summary(items)


def _phase_detail(phase: Dict[str, Any]) -> str:
    """Pull an optional human note off a phase result, tolerating any shape."""
    result = phase.get("result")
    if isinstance(result, dict):
        for key in ("detail", "reason", "message", "note"):
            value = result.get(key)
            if value:
                return _clean(value)
    return ""


# How a Full-Collection scan phase status (Title-case, from collection_runner)
# maps into coverage vocabulary.
_SCAN_STATUS_MAP = {
    "success": ("full", None),
    "error": ("failed", "failed_phase"),
    "skipped": ("skipped", "skipped_phase"),
}

# Substrings in a skip reason that indicate an optional capability was absent.
_MISSING_DEP_HINTS = (
    "not installed", "not available", "unavailable", "missing", "no binary",
    "requires ", "dependency", "playwright", "optional",
)


def _scan_skip_reason(result: Dict[str, Any], detail: str) -> str:
    """Classify a scan phase skip into a coverage reason code."""
    if result.get("scope_guard") or detail.lower().startswith("scope guard"):
        return "scope_denied"
    low = detail.lower()
    if any(hint in low for hint in _MISSING_DEP_HINTS):
        return "missing_dependency"
    return "skipped_phase"


def coverage_from_scan_report(report: Any, *, max_detail: int = 160) -> Dict[str, Any]:
    """Derive real per-scan coverage from a Full-Collection ``report`` dict.

    Reads ``report['phases']`` (each ``{status: Success|Error|Skipped, …}``) and
    turns the live phase outcomes into a coverage summary: a ``Success`` phase is
    ``full``, an ``Error`` is ``failed``/``failed_phase``, a ``Skipped`` phase is
    ``skipped`` with its reason classified (``scope_denied`` when Scope Guard
    blocked it, ``missing_dependency`` when an optional capability was absent,
    else ``skipped_phase``). Malformed input never raises.
    """
    if not isinstance(report, dict):
        return build_coverage_summary([])
    phases = report.get("phases")
    if not isinstance(phases, dict):
        return build_coverage_summary([])

    items: List[Dict[str, Any]] = []
    for name, result in phases.items():
        if not isinstance(result, dict):
            continue
        clean_name = _clean(name)
        if not clean_name:
            continue
        raw_status = _clean(result.get("status")).lower()
        status, reason = _SCAN_STATUS_MAP.get(raw_status, ("unavailable", None))
        detail = _clean(result.get("reason") or result.get("error"))
        if status == "skipped":
            reason = _scan_skip_reason(result, detail)
        if len(detail) > max_detail:
            detail = detail[:max_detail].rstrip() + "…"
        items.append(coverage_item(clean_name, status, reason, detail))
    return build_coverage_summary(items)


# --- Rendering ---------------------------------------------------------------

_STATUS_LABEL = {
    "full": "Full",
    "partial": "Partial",
    "skipped": "Skipped",
    "failed": "Failed",
    "unavailable": "Unavailable",
}


def _md_cell(value: Any) -> str:
    """Escape a value for a Markdown table cell (pipes/newlines are unsafe)."""
    return _clean(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def render_coverage_markdown(summary: Dict[str, Any]) -> str:
    """Render the "Limitations & Coverage" Markdown section from a summary.

    Accepts either a summary dict (from :func:`build_coverage_summary`) or a raw
    list of items, so callers can pass whatever they have.
    """
    if isinstance(summary, list):
        summary = build_coverage_summary(summary)
    elif not isinstance(summary, dict):
        summary = build_coverage_summary([])

    overall = _clean(summary.get("overall_status")) or "unavailable"
    total = int(summary.get("total") or 0)
    covered = int(summary.get("covered") or 0)
    ratio = summary.get("coverage_ratio") or 0.0
    pct = f"{round(float(ratio) * 100)}%" if total else "n/a"

    lines = [
        "## Limitations & Coverage",
        "",
        f"- Overall coverage: **{_STATUS_LABEL.get(overall, overall)}**",
        f"- Phases covered: {covered}/{total} ({pct})",
    ]

    items = summary.get("items") or []
    if not items:
        lines.extend(
            [
                "",
                "No coverage detail was recorded for this run.",
                "",
            ]
        )
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(
        [
            "",
            "| Phase | Coverage | Reason | Detail |",
            "|---|---|---|---|",
        ]
    )
    for item in items:
        if not isinstance(item, dict):
            continue
        status = _clean(item.get("status")) or "unavailable"
        lines.append(
            "| {phase} | {status} | {reason} | {detail} |".format(
                phase=_md_cell(item.get("phase")),
                status=_md_cell(_STATUS_LABEL.get(status, status)),
                reason=_md_cell(item.get("reason") or "-"),
                detail=_md_cell(item.get("detail") or "-"),
            )
        )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_coverage_html(summary: Dict[str, Any]) -> str:
    """Render the coverage section as an escaped, self-contained HTML fragment."""
    if isinstance(summary, list):
        summary = build_coverage_summary(summary)
    elif not isinstance(summary, dict):
        summary = build_coverage_summary([])

    overall = _clean(summary.get("overall_status")) or "unavailable"
    total = int(summary.get("total") or 0)
    covered = int(summary.get("covered") or 0)
    ratio = summary.get("coverage_ratio") or 0.0
    pct = f"{round(float(ratio) * 100)}%" if total else "n/a"

    header = (
        "<h2>Limitations &amp; Coverage</h2>"
        f"<p><b>Overall coverage:</b> {html.escape(_STATUS_LABEL.get(overall, overall))}"
        f" | <b>Phases covered:</b> {covered}/{total} ({html.escape(pct)})</p>"
    )
    items = summary.get("items") or []
    if not items:
        return header + "<p>No coverage detail was recorded for this run.</p>"

    body = []
    for item in items:
        if not isinstance(item, dict):
            continue
        status = _clean(item.get("status")) or "unavailable"
        body.append(
            "<tr>"
            f"<td>{html.escape(_clean(item.get('phase')))}</td>"
            f"<td>{html.escape(_STATUS_LABEL.get(status, status))}</td>"
            f"<td>{html.escape(_clean(item.get('reason')) or '-')}</td>"
            f"<td>{html.escape(_clean(item.get('detail')) or '-')}</td>"
            "</tr>"
        )
    return (
        header
        + "<table><thead><tr><th>Phase</th><th>Coverage</th>"
        "<th>Reason</th><th>Detail</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )
