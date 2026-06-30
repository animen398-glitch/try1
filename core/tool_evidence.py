"""core/tool_evidence.py
Captured-scan → tool-evidence bridge.

Turns a finished scan's ``report.json`` into the per-tool **evidence** dict that
the :mod:`core.tool_parsers` parsers consume — so a tool run can be driven from
data the platform already captured (passively, offline) instead of
operator-pasted JSON.

Pure: a ``dict → dict`` mapper over an already-loaded report (the caller obtains
it via :meth:`core.project.Project.load_scan_report`). No I/O, no network, no
store writes, and no tool execution. An **additive per-tool extractor registry**
(mirrors :data:`core.tool_parsers.PARSERS`); a tool with no extractor — or a
report lacking its data — yields ``{}`` (the caller then falls back to manual
evidence). Reuses the report shapes :mod:`core.collection_runner` writes.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List


def _phase_data(report: Dict[str, Any], phase: str) -> Dict[str, Any]:
    """``report['phases'][phase]['data']`` as a dict, or ``{}``."""
    phases = report.get('phases') if isinstance(report, dict) else None
    entry = phases.get(phase) if isinstance(phases, dict) else None
    data = entry.get('data') if isinstance(entry, dict) else None
    return data if isinstance(data, dict) else {}


def _target(report: Dict[str, Any]) -> str:
    return str((report or {}).get('url') or (report or {}).get('domain') or '')


def _extract_source_map_finder(report: Dict[str, Any]) -> Dict[str, Any]:
    """``{url, urls}`` from ``recon.data.source_maps`` (captured ``.map`` URLs)."""
    recon = _phase_data(report, 'recon')
    urls: List[str] = []
    for m in recon.get('source_maps') or []:
        if isinstance(m, dict) and m.get('url'):
            urls.append(str(m['url']))
    if not urls:
        return {}
    return {'url': _target(report), 'urls': urls}


def _extract_safe_active_prober(report: Dict[str, Any]) -> Dict[str, Any]:
    """``{subdomains}`` from the subdomains phase (enumerated results + takeover
    candidates), deduplicated."""
    sub = _phase_data(report, 'subdomains')
    subs: List[str] = []
    seen: set = set()

    def add(value: Any) -> None:
        clean = str(value or '').strip()
        if clean and clean not in seen:
            seen.add(clean)
            subs.append(clean)

    for r in sub.get('results') or []:
        add(r.get('subdomain') if isinstance(r, dict) else r)
    summary = sub.get('summary') if isinstance(sub.get('summary'), dict) else {}
    for c in summary.get('takeover_candidates') or []:
        add(c.get('subdomain') if isinstance(c, dict) else c)

    return {'subdomains': subs} if subs else {}


# Per-tool extractor registry, keyed by the M3 tool name (see
# tool_adapter.TOOL_CAPABILITIES / tool_parsers.PARSERS). Additive: a tool whose
# evidence is not reliably present in a passive scan report is simply absent here
# and falls back to manual evidence.
EXTRACTORS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    'source_map_finder': _extract_source_map_finder,
    'safe_active_prober': _extract_safe_active_prober,
}


def evidence_from_report(report: Dict[str, Any], tool: Any) -> Dict[str, Any]:
    """Per-tool evidence extracted from a scan ``report``, or ``{}`` if the tool
    has no extractor or the report lacks its data.

    The result is exactly the shape ``tool_parsers``' parser for ``tool``
    consumes, so it feeds straight into ``tool_pipeline.assemble_tool_run`` /
    ``tool_parsers.parse_tool_output``. Never raises."""
    from core.tool_adapter import normalize_tool_name
    try:
        name = normalize_tool_name(tool)
    except ValueError:
        return {}
    extractor = EXTRACTORS.get(name)
    if extractor is None:
        return {}
    rep = report if isinstance(report, dict) else {}
    try:
        out = extractor(rep)
    except Exception:   # noqa: BLE001 — a bridge must never crash the caller
        return {}
    return out if isinstance(out, dict) else {}


def available_tools(report: Dict[str, Any]) -> List[str]:
    """Tools with non-empty bridgeable evidence in this report (sorted)."""
    return sorted(t for t in EXTRACTORS if evidence_from_report(report, t))
