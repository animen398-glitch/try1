"""Path Prober — execute a wordlist plan (Roadmap E5 increment 2).

The :mod:`core.wordlist_manager` planner turns detected technologies + the ROE
budget into a *small, targeted, bounded* candidate list. This module is the safe
**executor** for such a plan: it issues one lightweight request per candidate
path through an **injectable fetch seam** and classifies whether the path exists,
is protected, or is absent. It adds no candidates of its own, sends nothing the
plan did not authorize, and is offline-testable because the transport is injected.

Design
------
- Pure classification + a thin request loop; the transport (``fetch``) is a
  callable ``(url) -> Optional[int]`` returning an HTTP status (or ``None`` on a
  network error). In production the caller passes a throttled HEAD/GET over the
  shared HTTP seam, so the scan's per-host rate limit paces every probe.
- Never brute-forces: the candidate count is already capped by the ROE budget in
  the planner; this executor only walks that bounded list once.
- Never raises — a transport error for one path is recorded as ``error`` and the
  walk continues.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin


# A probed path's existence state, derived from its HTTP status.
STATES = ("found", "protected", "absent", "other", "error")

# States that mean the resource is actually there (worth surfacing).
_PRESENT = ("found", "protected")


def classify_status(status: Optional[int]) -> str:
    """Map an HTTP status (or ``None``) to a path-existence state.

    ``2xx``/``3xx`` → ``found``; ``401``/``403`` → ``protected`` (it exists but is
    gated); ``404``/``410`` → ``absent``; any other status → ``other``; a
    transport failure (``None``) → ``error``.
    """
    if status is None:
        return "error"
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "error"
    if 200 <= code < 400:
        return "found"
    if code in (401, 403):
        return "protected"
    if code in (404, 410):
        return "absent"
    return "other"


def probe_paths(
    base_url: str,
    candidates: List[str],
    *,
    fetch: Callable[[str], Optional[int]],
    max_paths: Optional[int] = None,
) -> Dict[str, Any]:
    """Probe each candidate path under ``base_url`` and classify the outcome.

    Returns ``{results, found, summary}``:

    - ``results`` — one ``{path, url, status, state}`` per probed candidate.
    - ``found`` — the subset whose state means the resource is present
      (``found``/``protected``) — the operator's takeaway.
    - ``summary`` — ``{probed, present, by_state}`` counts.

    ``max_paths`` is a defensive final cap on top of the plan's budget. The
    ``fetch`` seam does the actual request; a ``None`` return (transport error)
    is recorded as ``error`` and never stops the walk.
    """
    paths = [p for p in (candidates or []) if isinstance(p, str) and p]
    if max_paths is not None:
        paths = paths[: max(0, int(max_paths))]

    results: List[Dict[str, Any]] = []
    by_state: Dict[str, int] = {state: 0 for state in STATES}
    for path in paths:
        url = urljoin(base_url, path) if base_url else path
        try:
            status = fetch(url)
        except Exception:  # noqa: BLE001 — one bad probe must not sink the phase
            status = None
        state = classify_status(status)
        by_state[state] += 1
        results.append({"path": path, "url": url,
                        "status": status, "state": state})

    found = [r for r in results if r["state"] in _PRESENT]
    return {
        "results": results,
        "found": found,
        "summary": {
            "probed": len(results),
            "present": len(found),
            "by_state": by_state,
        },
    }


# Curated map of genuinely-sensitive paths that, when publicly *readable*, are a
# finding (not merely recon surface). Keyed by the exact candidate path from
# core.wordlist_manager; the value is (severity, why). Paths absent here
# (robots.txt, /login, /admin, /health, /sitemap.xml, API endpoints, expected
# WordPress login pages, …) are normal surface and never become findings —
# precision-first, the same ethos as the wordlists themselves.
_SENSITIVE_PATHS = {
    # Version control / source exposure.
    "/.git/HEAD": ("High", "Exposed Git repository metadata"),
    "/.git/config": ("High", "Exposed Git repository config"),
    "/.svn/entries": ("High", "Exposed Subversion metadata"),
    "/.hg/store": ("High", "Exposed Mercurial store"),
    # Config / secrets / backups.
    "/.env": ("High", "Exposed environment file (likely secrets)"),
    "/.env.local": ("High", "Exposed environment file (likely secrets)"),
    "/config.php.bak": ("High", "Exposed config backup"),
    "/config.json": ("High", "Exposed configuration file"),
    "/settings.py.bak": ("High", "Exposed settings backup"),
    "/backup.zip": ("High", "Exposed backup archive"),
    # WordPress.
    "/wp-config.php.bak": ("High", "Exposed WordPress config backup"),
    "/wp-json/wp/v2/users": ("Medium", "WordPress user-enumeration endpoint"),
    "/xmlrpc.php": ("Low", "WordPress XML-RPC enabled"),
    # PHP info disclosure.
    "/info.php": ("Medium", "PHP info disclosure"),
    "/phpinfo.php": ("Medium", "PHP info disclosure"),
    "/test.php": ("Low", "Test script exposed"),
    # Django.
    "/__debug__/": ("High", "Django debug toolbar exposed"),
    # Laravel.
    "/telescope": ("High", "Laravel Telescope debug panel exposed"),
    "/storage/logs/laravel.log": ("High", "Exposed Laravel application log"),
    # Spring.
    "/actuator": ("Medium", "Spring Boot Actuator exposed"),
    "/actuator/env": ("High", "Spring Actuator env endpoint (secrets) exposed"),
    # Node.js.
    "/.npmrc": ("High", "Exposed .npmrc (likely an npm token)"),
    "/server.js.map": ("Medium", "Exposed JavaScript source map"),
    "/package.json": ("Low", "Exposed package.json"),
    # Tomcat.
    "/manager/html": ("High", "Tomcat Manager exposed"),
    "/host-manager/html": ("High", "Tomcat Host Manager exposed"),
    "/examples/": ("Medium", "Tomcat default example apps exposed"),
}


def exposure_findings(found, base_url: str = "") -> List[Dict[str, Any]]:
    """Turn *readable* sensitive probe hits into raw finding dicts (E5-2 fold).

    Only paths that are genuinely sensitive when public (:data:`_SENSITIVE_PATHS`)
    **and** were actually readable (state ``found`` — a 2xx/3xx, not an auth-gated
    ``protected``) become findings. Each is shaped like the other collection
    folders (``{severity, title, detail, source, category, location}``) so it
    flows through Findings Management (lifecycle / SLA / triage) and the risk
    score. Pure, deterministic, deduped by path.
    """
    findings: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for r in found or []:
        if not isinstance(r, dict) or r.get("state") != "found":
            continue
        path = r.get("path")
        entry = _SENSITIVE_PATHS.get(path)
        if not entry or path in seen:
            continue
        seen.add(path)
        severity, why = entry
        url = r.get("url") or (urljoin(base_url, path) if base_url else path)
        findings.append({
            "severity": severity,
            "title": f"Exposed sensitive path: {path}",
            "detail": f"{why} — {url} is publicly reachable "
                      f"(HTTP {r.get('status')}).",
            "source": "path-probe",
            "category": "exposed_path",
            "location": url,
        })
    return findings
