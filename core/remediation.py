"""core/remediation.py
Remediation Tasks — track the fix work for findings (EPIC NEXT F4).

A remediation task is a small, mutable work item attached to a finding: a status
(open / in_progress / done), an optional owner and due date, and a free note. It
lives **on top of the existing ``finding_events`` log** — one ``REMEDIATION`` event
per change, the task = the latest event's payload (event-sourced, no second table,
mirroring the ``ISSUE_CREATED`` mapping and the one-shot alert markers).

Pure / stdlib-only / offline: ``FindingsStore`` owns persistence
(``set_remediation`` / ``get_remediation`` / ``remediations``), this module owns the
vocabulary, the partial-update merge, the overdue derivation, and the rollup the
report card / web / CLI render. It is workflow state, not a scanner signal — it does
NOT touch the risk verdict.

"Top findings/paths" auto-seeding piggybacks on the priority ranking
(``intelligence.load_intelligence``): a finding on a critical exposure / attack path
already carries a high priority (F2/F3), so seeding the top-N priority findings
covers the path-relevant work without a fuzzy path→finding mapping.
"""

from datetime import datetime
from typing import Dict, List, Optional

REMEDIATION_STATUSES = ('open', 'in_progress', 'done')
DEFAULT_STATUS = 'open'
# Display labels (RU) — single source for the report card / CLI / future GUI.
STATUS_LABELS = {'open': 'Открыто', 'in_progress': 'В работе', 'done': 'Сделано'}
_STATUS_ORDER = {'open': 0, 'in_progress': 1, 'done': 2}


def _store():
    from core.findings_store import FindingsStore
    return FindingsStore()


def normalize_status(value) -> Optional[str]:
    v = str(value or '').strip().lower()
    return v if v in REMEDIATION_STATUSES else None


def normalize_task(payload) -> Dict[str, str]:
    """A task payload with a valid status (default ``open``) + trimmed optional
    owner / due / note (dropped when empty)."""
    p = payload if isinstance(payload, dict) else {}
    out: Dict[str, str] = {'status': normalize_status(p.get('status')) or DEFAULT_STATUS}
    for k in ('owner', 'due', 'note'):
        v = str(p.get(k) or '').strip()
        if v:
            out[k] = v
    return out


def merge_task(current, update) -> Dict[str, str]:
    """Apply a partial ``update`` over the ``current`` task: ``None`` fields keep the
    current value, an explicit empty string clears that field, a valid status
    replaces it. Returns a normalized task."""
    base = normalize_task(current)
    upd = update if isinstance(update, dict) else {}
    if upd.get('status') is not None:
        st = normalize_status(upd['status'])
        if st:
            base['status'] = st
    for k in ('owner', 'due', 'note'):
        if upd.get(k) is not None:
            v = str(upd[k]).strip()
            if v:
                base[k] = v
            else:
                base.pop(k, None)
    return base


def _parse_due(due: str) -> Optional[datetime]:
    """Parse a due value (ISO datetime or ``YYYY-MM-DD`` date → end of that day)."""
    s = str(due or '').strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        try:
            return datetime.fromisoformat(s + 'T23:59:59')
        except ValueError:
            return None


def is_overdue(task, now=None) -> bool:
    """A task is overdue when its due date is past and it is not done."""
    task = normalize_task(task)
    if task['status'] == 'done' or not task.get('due'):
        return False
    ref = now or datetime.now()
    if isinstance(ref, str):
        try:
            ref = datetime.fromisoformat(ref)
        except ValueError:
            return False
    due = _parse_due(task['due'])
    return bool(due and due < ref)


# ── management / derive (CLI / web / report) ──────────────────────────────────

def set_task(store, finding_id, *, status=None, owner=None, due=None, note=None,
             scan_id=None, now=None) -> Dict:
    """Create/update a finding's remediation task (partial update over current)."""
    task = merge_task(store.get_remediation(finding_id),
                      {'status': status, 'owner': owner, 'due': due, 'note': note})
    store.set_remediation(finding_id, task, scan_id=scan_id, now=now)
    return task


def auto_create_tasks(store, finding_ids, *, scan_id=None, now=None) -> List[str]:
    """Seed an ``open`` task for each finding that has none yet (idempotent).

    Returns the created ids — a finding that already has a task is left untouched, so
    this is safe to re-run (mirrors the create-only GitHub-issue sync)."""
    created: List[str] = []
    for fid in finding_ids or []:
        if fid and store.get_remediation(fid) is None:
            store.set_remediation(fid, normalize_task({'status': 'open'}),
                                  scan_id=scan_id, now=now)
            created.append(fid)
    return created


def seed_from_intelligence(project, *, top_n=10, business=None, store=None,
                           scan_id=None, now=None) -> List[str]:
    """Auto-create tasks for the project's top-N priority findings (F2/F3 ranking).

    A finding on a critical exposure / attack path already ranks high, so this
    covers "top findings/paths" without a path→finding mapping. Idempotent."""
    from core.intelligence import load_intelligence
    store = store or _store()
    items = (load_intelligence(project, business=business).get('top') or [])[:top_n]
    ids = [it.get('id') for it in items if it.get('id')]
    return auto_create_tasks(store, ids, scan_id=scan_id, now=now)


def load_remediation(project, *, store=None, now=None) -> Dict:
    """The project's remediation tasks + a rollup (thin reader, derive-on-read).

    Returns ``{tasks, summary}``: ``tasks`` carry the normalized task, an ``overdue``
    flag and a status label (overdue first, then by status, then title); ``summary``
    counts total / overdue / per-status. Offline, read-only; run off the GUI thread."""
    store = store or _store()
    by_status = {s: 0 for s in REMEDIATION_STATUSES}
    overdue = 0
    tasks: List[Dict] = []
    for r in store.remediations(project):
        task = normalize_task(r.get('task'))
        od = is_overdue(task, now)
        by_status[task['status']] = by_status.get(task['status'], 0) + 1
        overdue += 1 if od else 0
        tasks.append({**r, 'task': task, 'overdue': od,
                      'status_label': STATUS_LABELS.get(task['status'], task['status'])})
    tasks.sort(key=lambda t: (0 if t['overdue'] else 1,
                              _STATUS_ORDER.get(t['task']['status'], 9),
                              str(t.get('title') or '')))
    summary = {'total': len(tasks), 'overdue': overdue,
               'open': by_status.get('open', 0),
               'in_progress': by_status.get('in_progress', 0),
               'done': by_status.get('done', 0)}
    return {'tasks': tasks, 'summary': summary}
