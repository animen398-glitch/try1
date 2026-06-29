"""core/tool_parsers.py
Per-tool offline parsers — the safe layer above the Tool Adapter Contract (M3).

A parser turns a tool's *already-captured* evidence (a plain dict — never a live
tool run, never a socket) into the generic ``{"findings": [...], "assets": [...]}``
shape that :func:`core.tool_adapter.map_tool_result_to_findings` consumes.

Detection logic is **reused, not re-implemented**: the header / cookie / source-map
parsers defer to the existing :mod:`core.audit_checks`. Scope/ROE gating is *not*
the parser's job — that belongs to the adapter
(:func:`core.tool_adapter.evaluate_tool_allowed_for_mission`) — so a parser runs
its reused check under a permissive in-scope ROE just to bypass the check's own
gate; the real authorization decision happens before a tool is ever run.

Pure / offline / deterministic. No network, no store writes, no new dependencies,
and no exploit/bruteforce/stealth/payload behaviour.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from core import audit_checks
from core.scope_guard import host_from_url


def _permissive_roe(target: str) -> Dict[str, Any]:
    """An in-scope, active-allowed ROE so the reused check's own gate passes.

    This is *not* an authorization decision — that already happened in
    ``evaluate_tool_allowed_for_mission`` before any tool ran. It only lets the
    detection logic in ``audit_checks`` execute against captured evidence."""
    host = host_from_url(target)
    return {
        "profile": "client_safe",
        "allowed_domains": [host] if host else [],
        "active_scan_enabled": True,
        "passive_only": False,
    }


def _domain_asset(target: str, source: str) -> List[Dict[str, str]]:
    host = host_from_url(target)
    return [{"value": host, "asset_type": "domain", "source": source}] if host else []


def _adapt_findings(checks_findings: Any, target: str) -> List[Dict[str, Any]]:
    """Map ``audit_checks`` findings onto the adapter's raw finding shape."""
    out: List[Dict[str, Any]] = []
    for finding in checks_findings or []:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        location = str(finding.get("location") or target)
        out.append({
            "title": str(finding.get("title") or ""),
            "severity": str(finding.get("severity") or "info"),
            "asset": host_from_url(location) or host_from_url(target),
            "location": location,
            "evidence_refs": list(evidence.get("evidence_refs") or []),
        })
    return out


def parse_header_audit(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Captured ``{"url", "headers"}`` → missing-security-header findings."""
    data = evidence if isinstance(evidence, dict) else {}
    target = str(data.get("url") or data.get("target") or "")
    result = audit_checks.headers_check(
        target, _permissive_roe(target),
        evidence={"headers": data.get("headers") or {}})
    return {
        "findings": _adapt_findings(result.get("findings"), target),
        "assets": _domain_asset(target, "header_audit"),
    }


def parse_cookie_audit(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Captured ``{"url", "cookies"}`` → missing cookie-flag findings."""
    data = evidence if isinstance(evidence, dict) else {}
    target = str(data.get("url") or data.get("target") or "")
    result = audit_checks.cookie_flags_check(
        target, _permissive_roe(target),
        evidence={"cookies": data.get("cookies") or []})
    return {
        "findings": _adapt_findings(result.get("findings"), target),
        "assets": _domain_asset(target, "cookie_audit"),
    }


def parse_source_map_finder(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Captured ``{"urls"}`` → exposed source-map findings (``.map`` URLs)."""
    data = evidence if isinstance(evidence, dict) else {}
    urls = [str(url) for url in (data.get("urls") or [])]
    target = str(data.get("url") or data.get("target") or "")
    if not target and urls:
        target = urls[0]
    result = audit_checks.source_map_detection(
        target, _permissive_roe(target), evidence={"urls": urls})
    return {
        "findings": _adapt_findings(result.get("findings"), target),
        "assets": _domain_asset(target, "source_map_finder"),
    }


def parse_safe_active_prober(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Captured ``{"urls", "hosts", "subdomains"}`` → normalized assets (no
    findings). The asset/enumeration parser of this first layer."""
    data = evidence if isinstance(evidence, dict) else {}
    assets: List[Dict[str, str]] = []
    seen: set[tuple] = set()

    def add(value: str, asset_type: str) -> None:
        clean = str(value or "").strip()
        if not clean:
            return
        key = (asset_type, clean)
        if key not in seen:
            seen.add(key)
            assets.append({"value": clean, "asset_type": asset_type,
                           "source": "safe_active_prober"})

    for url in data.get("urls") or []:
        add(str(url).strip(), "url")
    for host in data.get("hosts") or []:
        add(host_from_url(host) or str(host), "subdomain")
    for sub in data.get("subdomains") or []:
        add(host_from_url(sub) or str(sub), "subdomain")
    return {"findings": [], "assets": assets}


# Parser registry keyed by the M3 tool name (see tool_adapter.TOOL_CAPABILITIES).
# Tools without a parser yet are simply absent — adding one is purely additive.
PARSERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "header_audit": parse_header_audit,
    "cookie_audit": parse_cookie_audit,
    "source_map_finder": parse_source_map_finder,
    "safe_active_prober": parse_safe_active_prober,
}


def has_parser(tool: str) -> bool:
    """True if a parser is registered for ``tool``."""
    from core.tool_adapter import normalize_tool_name
    try:
        name = normalize_tool_name(tool)
    except ValueError:
        return False
    return name in PARSERS


def parse_tool_output(tool: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch captured ``evidence`` to ``tool``'s parser.

    Returns the generic ``{"findings": [...], "assets": [...]}`` shape, ready for
    :func:`core.tool_adapter.map_tool_result_to_findings`. An empty/unknown tool,
    or a tool with no registered parser, is rejected. Never runs a tool, opens a
    socket, or writes to a store.
    """
    from core.tool_adapter import normalize_tool_name
    name = normalize_tool_name(tool)
    parser = PARSERS.get(name)
    if parser is None:
        raise ValueError(f"no parser for tool: {name}")
    out = parser(evidence if isinstance(evidence, dict) else {})
    return {
        "findings": list(out.get("findings") or []),
        "assets": list(out.get("assets") or []),
    }
