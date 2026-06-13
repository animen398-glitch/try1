"""core/findings_status.py
Findings Management — durable triage state over a project's findings
(roadmap #14).

A Full Collection produces findings every run, but their *lifecycle* — is this
one new, being worked, fixed, or a known false-positive? — is the analyst's, not
the scanner's. This module keeps that lifecycle: each finding gets a stable
fingerprint, and a per-project state map remembers its status
(``open`` / ``in_progress`` / ``fixed`` / ``ignored``) and a note across scans.

A finding marked ``fixed`` or ``ignored`` is *inactive*: it stops counting
toward the risk engine (see ``core.executive_summary``), so triaging a
false-positive actually lowers the score — while the record is kept, so if the
same issue resurfaces in a later scan it is visible again.

Pure and stdlib-only (architectural invariants I1/I2/I5): every function is a
pure transform over plain dicts. ``core.project`` owns persistence
(``findings.json``); the GUI/report stay thin callers.
"""

import hashlib
import html
import re
from datetime import datetime
from typing import Dict, List, Optional

# The triage lifecycle. ``open`` is the implicit state of every newly seen
# finding; ``fixed``/``ignored`` are *inactive* (excluded from the risk engine).
STATUSES = ('open', 'in_progress', 'fixed', 'ignored')
DEFAULT_STATUS = 'open'
INACTIVE_STATUSES = frozenset({'fixed', 'ignored'})

STATUS_LABELS = {
    'open': 'Открыто', 'in_progress': 'В работе',
    'fixed': 'Исправлено', 'ignored': 'Игнор',
}
_STATUS_COLORS = {
    'open': '#c62828', 'in_progress': '#f9a825',
    'fixed': '#2e7d32', 'ignored': '#888',
}

_NUM_RE = re.compile(r'\d+')
_WS_RE = re.compile(r'\s+')


def _now(now: Optional[str] = None) -> str:
    # Local time, matching core.project (these are audit/display stamps, not
    # compared against any external UTC clock).
    return now or datetime.now().isoformat(timespec='seconds')


def _norm_title(title) -> str:
    """Lower-case a title and mask volatile counts so identity is stable.

    ``Missing security headers (3)`` and ``… (4)`` must fingerprint to the same
    finding, so any run of digits collapses to ``#``."""
    t = _NUM_RE.sub('#', str(title or '').lower())
    return _WS_RE.sub(' ', t).strip()


def fingerprint(finding: Dict) -> str:
    """A stable short id for a finding from severity + source + normalized title.

    Stable across scans (so a status sticks) and across volatile count changes
    in the title, but distinct for genuinely different findings."""
    sev = str(finding.get('severity', '')).lower()
    src = str(finding.get('source', '')).lower()
    base = f'{sev}|{src}|{_norm_title(finding.get("title", ""))}'
    return hashlib.sha1(base.encode('utf-8')).hexdigest()[:12]


def _record(finding: Dict, fp: str, now: str, scan_id: Optional[str]) -> Dict:
    return {
        'fingerprint': fp,
        'title': str(finding.get('title', '')),
        'severity': str(finding.get('severity', '')),
        'source': str(finding.get('source', '')),
        'status': DEFAULT_STATUS,
        'note': '',
        'first_seen': now,
        'last_seen': now,
        'first_scan': scan_id,
        'last_scan': scan_id,
        'present': True,
    }


def apply(state: Optional[Dict], findings: List[Dict],
          now: Optional[str] = None, scan_id: Optional[str] = None) -> Dict:
    """Merge a scan's ``findings`` into the prior ``state``, returning new state.

    Pure (never mutates ``state``). A finding not seen before is registered
    ``open``; a known one keeps its status/note but refreshes title/severity and
    its ``last_seen``/``last_scan``. Findings absent from this scan are kept with
    ``present=False`` (a triaged issue that resurfaces is re-flagged ``present``).
    """
    now = _now(now)
    # Copy prior records, resetting presence — re-set True for whatever we see.
    new_state: Dict[str, Dict] = {}
    for fp, rec in (state or {}).items():
        if isinstance(rec, dict):
            new_state[fp] = {**rec, 'present': False}

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        fp = fingerprint(finding)
        rec = new_state.get(fp)
        if rec is None:
            new_state[fp] = _record(finding, fp, now, scan_id)
        else:
            rec['present'] = True
            rec['last_seen'] = now
            rec['last_scan'] = scan_id
            # Refresh display fields to the latest wording/severity.
            rec['title'] = str(finding.get('title', rec.get('title', '')))
            rec['severity'] = str(finding.get('severity', rec.get('severity', '')))
            if not rec.get('source'):
                rec['source'] = str(finding.get('source', ''))
    return new_state


def set_status(state: Dict, fp: str, status: str, now: Optional[str] = None,
               note: Optional[str] = None) -> Dict:
    """Return new state with finding ``fp`` set to ``status`` (+ optional note).

    Raises ``ValueError`` for an unknown status and ``KeyError`` for an unknown
    fingerprint."""
    if status not in STATUSES:
        raise ValueError(f'unknown status: {status!r} (expected one of {STATUSES})')
    if fp not in (state or {}):
        raise KeyError(fp)
    rec = {**state[fp], 'status': status, 'updated_at': _now(now)}
    if note is not None:
        rec['note'] = str(note)
    return {**state, fp: rec}


def is_active(record: Dict) -> bool:
    """A record counts toward risk unless it's fixed/ignored."""
    return record.get('status') not in INACTIVE_STATUSES


def decorate(findings: List[Dict], state: Optional[Dict]) -> List[Dict]:
    """Return ``findings`` annotated with their ``status``/``fingerprint``.

    Pure (returns new dicts). Unknown findings default to ``open`` so a report
    rendered before any triage still carries a coherent status."""
    state = state or {}
    out: List[Dict] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fp = fingerprint(f)
        rec = state.get(fp) or {}
        out.append({**f, 'fingerprint': fp,
                    'status': rec.get('status', DEFAULT_STATUS)})
    return out


def summarize(state: Optional[Dict]) -> Dict:
    """Counts by status plus active/present/total over a state map (pure)."""
    by_status = {s: 0 for s in STATUSES}
    present = active = 0
    for rec in (state or {}).values():
        if not isinstance(rec, dict):
            continue
        status = rec.get('status', DEFAULT_STATUS)
        by_status[status] = by_status.get(status, 0) + 1
        if rec.get('present'):
            present += 1
        if is_active(rec):
            active += 1
    return {'total': sum(by_status.values()), 'by_status': by_status,
            'active': active, 'present': present}


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

_SEV_ORDER = {'High': 0, 'Medium': 1, 'Info': 2}


def render_html(state: Optional[Dict]) -> str:
    """Render the triage state as an offline HTML fragment."""
    e = html.escape
    records = [r for r in (state or {}).values() if isinstance(r, dict)]
    if not records:
        return ('<p style="font-size:13px;color:#999;">'
                'Находок под триаж пока нет</p>')

    s = summarize(state)
    bs = s['by_status']
    head = (f'<p style="font-size:13px;">Находок под управлением: '
            f'<b>{e(str(s["total"]))}</b> '
            f'(активных: {e(str(s["active"]))}; '
            + ', '.join(f'{e(STATUS_LABELS[st])}: {e(str(bs[st]))}'
                        for st in STATUSES)
            + ')</p>')

    # Active first, then by severity, then by status order.
    def sort_key(r):
        return (is_active(r) is False,
                _SEV_ORDER.get(r.get('severity'), 3),
                STATUSES.index(r.get('status', DEFAULT_STATUS))
                if r.get('status') in STATUSES else 9)

    rows = []
    for r in sorted(records, key=sort_key):
        status = r.get('status', DEFAULT_STATUS)
        color = _STATUS_COLORS.get(status, '#555')
        badge = (f'<span style="background:{color};color:#fff;border-radius:3px;'
                 f'padding:1px 6px;font-size:11px;">'
                 f'{e(STATUS_LABELS.get(status, status))}</span>')
        gone = ('' if r.get('present')
                else ' <span style="color:#bbb;font-size:11px;">'
                     '(не обнаружено в посл. скане)</span>')
        note = (f'<div style="color:#888;font-size:11px;margin-top:1px;">'
                f'{e(r.get("note", ""))}</div>' if r.get('note') else '')
        rows.append(
            f'<tr><td style="padding:2px 10px 2px 0;white-space:nowrap;">{badge}</td>'
            f'<td style="padding:2px 10px 2px 0;color:#666;font-size:12px;">'
            f'{e(str(r.get("severity", "")))}</td>'
            f'<td style="font-size:12px;">{e(str(r.get("title", "")))}{gone}{note}'
            f'</td></tr>')
    return head + (f'<table style="font-size:13px;border-collapse:collapse;'
                   f'margin-top:4px;">{"".join(rows)}</table>')
