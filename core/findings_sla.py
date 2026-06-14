"""core/findings_sla.py
SLA tracking for findings — DefectDojo-style remediation deadlines (pure).

A finding's SLA is a severity-based remediation window: an active finding older
than its window has *breached* SLA. This is derived on read from the stored
``first_seen_at`` + ``severity`` (no schema change, no second table — the same
derive-on-read approach as Timeline/F2). Policy lives here, not in the store.

Pure and stdlib-only (architectural invariants I1/I5): no DB, no network.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from core.findings_store import INACTIVE_STATUSES

# Remediation window per severity, in days (DefectDojo defaults). ``info`` has no
# SLA. A caller may override via ``settings['findings_sla']`` (same keys).
DEFAULT_SLA = {'critical': 7, 'high': 30, 'medium': 90, 'low': 120}


def sla_days(severity: str, overrides: Optional[Dict] = None) -> Optional[int]:
    """SLA window (days) for a severity, or ``None`` if the severity has no SLA
    (``info`` / unknown). ``overrides`` (e.g. from settings) wins over defaults."""
    sev = str(severity or '').strip().lower()
    table = {**DEFAULT_SLA, **(overrides or {})}
    val = table.get(sev)
    return int(val) if isinstance(val, (int, float)) and val > 0 else None


def _parse(ts) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        return None


def sla_status(finding: Dict, now: Optional[datetime] = None,
               overrides: Optional[Dict] = None) -> Dict:
    """SLA state for one stored finding row.

    Returns ``{'applicable': bool, ...}``. SLA only applies to *active* findings
    (status not in INACTIVE) whose severity has a window; otherwise
    ``{'applicable': False}``. When applicable:
    ``{applicable, age_days, sla_days, due_at, breached, days_left}`` —
    ``days_left`` is negative when overdue (= days past the deadline)."""
    status = str(finding.get('status') or '').upper()
    if status in INACTIVE_STATUSES:
        return {'applicable': False}
    window = sla_days(finding.get('severity'), overrides)
    first_seen = _parse(finding.get('first_seen_at'))
    if window is None or first_seen is None:
        return {'applicable': False}

    now = now or datetime.now()
    due = first_seen + timedelta(days=window)
    age_days = (now - first_seen).days
    days_left = (due - now).days
    return {
        'applicable': True,
        'age_days': age_days,
        'sla_days': window,
        'due_at': due.isoformat(timespec='seconds'),
        'breached': now > due,
        'days_left': days_left,
    }


def annotate(findings: List[Dict], now: Optional[datetime] = None,
             overrides: Optional[Dict] = None) -> List[Dict]:
    """Attach an ``sla`` dict to each stored finding row (in place) and return
    the list — the read-side helper for the GUI / report / web."""
    now = now or datetime.now()
    for f in findings or []:
        if isinstance(f, dict):
            f['sla'] = sla_status(f, now, overrides)
    return findings


def label(sla: Optional[Dict]) -> str:
    """Short RU label for an ``sla`` dict — single source for GUI/report/web so
    the wording never drifts. '—' when SLA doesn't apply."""
    if not sla or not sla.get('applicable'):
        return '—'
    days = sla.get('days_left', 0)
    if sla.get('breached'):
        return f'просрочено {abs(days)}д'
    return f'осталось {days}д'


def breached_count(findings: List[Dict], now: Optional[datetime] = None,
                   overrides: Optional[Dict] = None) -> int:
    """How many of these findings have breached their SLA (active + overdue)."""
    now = now or datetime.now()
    return sum(1 for f in (findings or [])
               if isinstance(f, dict) and sla_status(f, now, overrides)
               .get('breached'))
