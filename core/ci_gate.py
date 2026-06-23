"""CI/CD gate (EPIC 16 F4) — pure pass/fail policy over scan-diff events.

A pipeline runs a scan, diffs it against the baseline, and fails the build when a
**new** finding at/above a severity threshold appears (the standard "don't let new
high/critical issues merge" gate). This module is the pure policy; the CLI
(``monitor_cli ci``) wires the scan + ``scan_diff.diff_events`` to it and turns the
result into a process exit code. No I/O, no network — fully unit-testable.
"""

from typing import Dict, List, Optional

from core.severity import RANK as _RANK  # platform severity ranking SSOT (critical worst)


def evaluate_gate(events: Optional[List[Dict]], *, fail_on: str = 'high') -> Dict:
    """Decide pass/fail from scan-diff ``events`` (``{type, title, severity, ...}``).

    Fails when any event's severity is at/above ``fail_on`` (default ``high``).
    Returns ``{fail, fail_on, triggers, counts, total}``; an empty/None event list
    (e.g. the first scan with no baseline) passes."""
    threshold = _RANK.get(str(fail_on or 'high').lower(), 3)
    triggers: List[Dict] = []
    counts: Dict[str, int] = {}
    for e in (events or []):
        if not isinstance(e, dict):
            continue
        sev = str(e.get('severity', 'info')).lower()
        if _RANK.get(sev, 0) >= threshold:
            triggers.append(e)
            counts[sev] = counts.get(sev, 0) + 1
    return {'fail': bool(triggers), 'fail_on': str(fail_on or 'high').lower(),
            'triggers': triggers, 'counts': counts, 'total': len(triggers)}


def exit_code(result: Optional[Dict]) -> int:
    """Process exit code for a gate result: 1 on fail, 0 on pass."""
    return 1 if (result or {}).get('fail') else 0


def summary_line(result: Optional[Dict]) -> str:
    """One-line human summary of a gate result (for CI logs)."""
    r = result or {}
    fail_on = r.get('fail_on', 'high')
    if not r.get('fail'):
        return f'CI gate PASS — no new findings at/above {fail_on}'
    parts = ', '.join(f'{n} {sev}'
                      for sev, n in sorted(r.get('counts', {}).items()))
    return (f'CI gate FAIL — {r.get("total", 0)} new finding(s) '
            f'({parts}) at/above {fail_on}')
