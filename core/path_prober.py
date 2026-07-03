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
