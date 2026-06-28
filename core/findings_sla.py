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
from core.severity import SEVERITY_ORDER as _SEVERITY_ORDER

# Remediation window per severity, in days (DefectDojo defaults). ``info`` has no
# SLA. A caller may override via ``settings['findings_sla']`` (same keys).
DEFAULT_SLA = {'critical': 7, 'high': 30, 'medium': 90, 'low': 120}

# Default "due soon" warning band: an active, not-yet-breached finding with this
# many days (or fewer) left is flagged so a breach can be pre-empted, not just
# reported after the fact. Callers may pass their own ``warn_days``.
SLA_WARN_DAYS = 7

# KEV/EPSS → SLA tightening (decision, 2026-06-28). A finding carrying a real
# exploitability ``threat`` block (KEV / high EPSS — added by ``threat_intel``)
# must be remediated faster than its severity default: the remediation window is
# multiplied by the tier's factor. This is a *floor* — a window can only shrink,
# never grow — and self-gates on the threat block, so an un-enriched finding is
# untouched. Only the cached KEV/EPSS signal tightens SLA; the static priority
# heuristic (``intelligence._threat_tier``) deliberately does NOT — a class guess
# is grounds to re-rank, not to slash a deadline. Callers may override per tier
# via ``threat_mult`` (e.g. from settings); 1.0 / out-of-range disables a tier.
THREAT_SLA_MULTIPLIER = {'high': 0.25, 'medium': 0.5}


def _threat_signal(finding: Dict) -> tuple:
    """The exploitability tightening signal from a finding's cached ``threat``
    block: ``(tier, source)`` where tier is ``'high'``/``'medium'`` and source is
    ``'kev'``/``'epss'``. ``(None, None)`` when there is no qualifying block — the
    self-gate that keeps un-enriched findings on their plain severity SLA."""
    threat = finding.get('threat') if isinstance(finding, dict) else None
    if not isinstance(threat, dict):
        return (None, None)
    tier = threat.get('tier')
    if tier not in ('high', 'medium'):
        return (None, None)
    return (tier, 'kev' if threat.get('kev') else 'epss')


def _tighten(window: Optional[int], finding: Dict,
             threat_mult: Optional[Dict]) -> tuple:
    """Apply KEV/EPSS tightening to a severity ``window`` (days). Returns
    ``(effective_window, tightened_by)`` — ``tightened_by`` is ``'kev'``/``'epss'``
    when the window was shortened, else ``None``. Floor semantics: never grows."""
    if window is None:
        return (window, None)
    tier, source = _threat_signal(finding)
    if not tier:
        return (window, None)
    table = {**THREAT_SLA_MULTIPLIER, **(threat_mult or {})}
    mult = table.get(tier)
    if not isinstance(mult, (int, float)) or not 0 < mult < 1:
        return (window, None)
    eff = max(1, round(window * mult))
    return (eff, source) if eff < window else (window, None)


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


def _sev(value) -> str:
    s = str(value or '').strip().lower()
    return s if s in _SEVERITY_ORDER else 'info'


def _reference(finding: Dict, reopened_at=None) -> Optional[datetime]:
    """The date the SLA clock starts for the *current* open episode.

    A finding that was fixed and later reappears (REOPENED) gets a fresh
    remediation window — the deadline applies to the current episode, not the
    original discovery (DefectDojo semantics). So the reference is the latest of
    ``first_seen_at`` and the reopen date; the historical ``first_seen_at`` is
    preserved untouched for display. ``reopened_at`` is ``None`` for findings
    that never reopened (the common case → reference == first_seen)."""
    first = _parse(finding.get('first_seen_at'))
    reop = _parse(reopened_at)
    if first and reop:
        return max(first, reop)
    return reop or first


def sla_bucket(sla: Optional[Dict], warn_days: int = SLA_WARN_DAYS) -> Optional[str]:
    """Classify an ``sla`` dict into ``breached`` / ``due_soon`` / ``on_track``
    (or ``None`` when SLA does not apply). The single classifier so the report,
    GUI and summary never disagree on what "due soon" means."""
    if not sla or not sla.get('applicable'):
        return None
    if sla.get('breached'):
        return 'breached'
    return 'due_soon' if sla.get('days_left', 0) <= warn_days else 'on_track'


def sla_status(finding: Dict, now: Optional[datetime] = None,
               overrides: Optional[Dict] = None, reopened_at=None,
               warn_days: int = SLA_WARN_DAYS,
               threat_mult: Optional[Dict] = None) -> Dict:
    """SLA state for one stored finding row.

    Returns ``{'applicable': bool, ...}``. SLA only applies to *active* findings
    (status not in INACTIVE) whose severity has a window; otherwise
    ``{'applicable': False}``. When applicable:
    ``{applicable, age_days, sla_days, base_sla_days, tightened_by, due_at,
    breached, days_left, reference_at, bucket}`` — ``sla_days`` is the *effective*
    window after any KEV/EPSS tightening (``base_sla_days`` is the pre-tightening
    severity window, ``tightened_by`` is ``'kev'``/``'epss'``/``None``), so every
    derived value (due/breach/days_left/bucket) reflects the shortened deadline;
    ``days_left`` is negative when overdue (= days past the deadline),
    ``reference_at`` is the clock-start date (reopen-aware, see ``_reference``)."""
    status = str(finding.get('status') or '').upper()
    if status in INACTIVE_STATUSES:
        return {'applicable': False}
    base_window = sla_days(finding.get('severity'), overrides)
    reference = _reference(finding, reopened_at)
    if base_window is None or reference is None:
        return {'applicable': False}

    window, tightened_by = _tighten(base_window, finding, threat_mult)
    now = now or datetime.now()
    due = reference + timedelta(days=window)
    age_days = (now - reference).days
    days_left = (due - now).days
    sla = {
        'applicable': True,
        'age_days': age_days,
        'sla_days': window,
        'base_sla_days': base_window,
        'tightened_by': tightened_by,
        'due_at': due.isoformat(timespec='seconds'),
        'breached': now > due,
        'days_left': days_left,
        'reference_at': reference.isoformat(timespec='seconds'),
    }
    sla['bucket'] = sla_bucket(sla, warn_days)
    return sla


def annotate(findings: List[Dict], now: Optional[datetime] = None,
             overrides: Optional[Dict] = None, reopened: Optional[Dict] = None,
             warn_days: int = SLA_WARN_DAYS,
             threat_mult: Optional[Dict] = None) -> List[Dict]:
    """Attach an ``sla`` dict to each stored finding row (in place) and return
    the list — the read-side helper for the GUI / report / web.

    ``reopened`` is an optional ``{finding_id: reopen_timestamp}`` map (see
    ``FindingsStore.reopen_dates``) so the SLA clock restarts on reopen; absent
    it, the window is measured from ``first_seen_at`` as before. A finding
    already carrying a KEV/EPSS ``threat`` block gets a tightened deadline
    (see ``THREAT_SLA_MULTIPLIER``)."""
    now = now or datetime.now()
    reopened = reopened or {}
    for f in findings or []:
        if isinstance(f, dict):
            f['sla'] = sla_status(f, now, overrides, reopened.get(f.get('id')),
                                  warn_days, threat_mult)
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
                   overrides: Optional[Dict] = None,
                   reopened: Optional[Dict] = None,
                   threat_mult: Optional[Dict] = None) -> int:
    """How many of these findings have breached their SLA (active + overdue)."""
    now = now or datetime.now()
    reopened = reopened or {}
    return sum(1 for f in (findings or [])
               if isinstance(f, dict)
               and sla_status(f, now, overrides, reopened.get(f.get('id')),
                              threat_mult=threat_mult)
               .get('breached'))


def _age_bucket(days: int) -> str:
    """Coarse age band for the aging histogram (mirrors the SLA windows)."""
    if days <= 7:
        return '0-7'
    if days <= 30:
        return '8-30'
    if days <= 90:
        return '31-90'
    return '90+'


def sla_summary(findings: List[Dict], now: Optional[datetime] = None,
                overrides: Optional[Dict] = None, reopened: Optional[Dict] = None,
                warn_days: int = SLA_WARN_DAYS,
                threat_mult: Optional[Dict] = None) -> Dict:
    """Aggregate SLA posture over a list of findings (pure, derive-on-read).

    Returns ``{applicable, breached, due_soon, on_track, by_severity, aging}`` —
    bucket counts (only findings with an SLA), a per-severity breakdown, and an
    aging histogram keyed by age band. Reopen-aware via ``reopened``. Findings
    carrying a KEV/EPSS ``threat`` block use their tightened deadline."""
    now = now or datetime.now()
    reopened = reopened or {}
    buckets = {'breached': 0, 'due_soon': 0, 'on_track': 0}
    by_severity: Dict[str, Dict[str, int]] = {}
    aging = {'0-7': 0, '8-30': 0, '31-90': 0, '90+': 0}
    applicable = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        st = sla_status(f, now, overrides, reopened.get(f.get('id')), warn_days,
                        threat_mult)
        if not st.get('applicable'):
            continue
        applicable += 1
        bucket = st.get('bucket')
        if bucket in buckets:
            buckets[bucket] += 1
        sev = _sev(f.get('severity'))
        row = by_severity.setdefault(
            sev, {'breached': 0, 'due_soon': 0, 'on_track': 0, 'total': 0})
        if bucket in row:
            row[bucket] += 1
        row['total'] += 1
        aging[_age_bucket(st.get('age_days', 0))] += 1
    return {'applicable': applicable, **buckets,
            'by_severity': by_severity, 'aging': aging}


def sla_events(findings: List[Dict], now: Optional[datetime] = None,
               overrides: Optional[Dict] = None,
               reopened: Optional[Dict] = None,
               threat_mult: Optional[Dict] = None) -> List[Dict]:
    """Timeline-shaped events for currently breached findings (pure, F2 feed).

    A breach happens by the passage of time, not by a scan, so it has no natural
    scan event — we derive one per active+breached finding, dated at its
    ``due_at`` (the moment it slipped). Shape matches ``timeline.build_events``
    rows: ``{scan_id: None, at, type: 'sla_breach', title, severity, section}``.
    De-dup/ordering are handled by the timeline builder."""
    now = now or datetime.now()
    reopened = reopened or {}
    out: List[Dict] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        st = sla_status(f, now, overrides, reopened.get(f.get('id')),
                        threat_mult=threat_mult)
        if not (st.get('applicable') and st.get('breached')):
            continue
        sev = _sev(f.get('severity'))
        title = f"[{sev}] {f.get('title') or ''} — SLA просрочено".strip()
        out.append({'scan_id': None, 'at': st.get('due_at'),
                    'type': 'sla_breach', 'title': title,
                    'severity': sev, 'section': 'findings'})
    return out
