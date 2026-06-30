"""core/retention.py
Scan retention — prune bulky scan *artifact* directories while keeping the index.

A scan is ``Projects/<slug>/scans/<id>/`` (the heavy capture/recon/report tree)
plus a cheap ``metadata.json`` ``scans[]`` entry and a ``history/<id>.json``
snapshot. Retention deletes only the artifact directory beyond a keep policy; the
metadata entry (marked ``artifacts_pruned``) and the history snapshot stay. So the
risk series/trend stay intact, the timeline degrades softly (a missing
``report.json`` is already skipped, never faked), and ``FindingsStore`` rows are
never orphaned (``scan_id`` is only a label).

Pure planner (:func:`plan_retention`) + an apply step (:func:`apply_retention`)
that performs the filesystem deletes and the additive metadata mark. Offline,
stdlib only. Disabled by default in settings — zero behaviour change until a
policy is set.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional


def _scan_dt(entry: Dict) -> Optional[datetime]:
    """Best-effort timestamp for a scan entry: ``finished_at`` (ISO) first, else
    the scan id (``%Y%m%d_%H%M%S`` with an optional ``-N`` collision suffix)."""
    finished = entry.get('finished_at')
    if finished:
        try:
            return datetime.fromisoformat(str(finished))
        except ValueError:
            pass
    sid = str(entry.get('id') or '')
    if sid:
        try:
            return datetime.strptime(sid.split('-')[0], '%Y%m%d_%H%M%S')
        except ValueError:
            pass
    return None


def plan_retention(project, *, keep_last: Optional[int] = None,
                   keep_days: Optional[int] = None,
                   now: Optional[datetime] = None) -> Dict[str, List[str]]:
    """Decide which scans to keep vs prune (pure — no filesystem writes).

    Scans are ordered by id (a timestamp). The newest scan is ALWAYS kept. A scan
    is kept if it is within the newest ``keep_last`` OR newer than ``keep_days``
    days; everything else is pruned. With no policy (both ``None``/<=0) nothing is
    pruned. An entry already marked ``artifacts_pruned`` is never re-listed.
    Returns ``{'keep': [ids], 'prune': [ids]}`` (ascending by id)."""
    entries = sorted(
        (s for s in project.scans() if isinstance(s, dict) and s.get('id')),
        key=lambda s: str(s.get('id')))
    ids = [str(s['id']) for s in entries]
    if not ids:
        return {'keep': [], 'prune': []}

    has_last = keep_last is not None and keep_last > 0
    has_days = keep_days is not None and keep_days > 0
    if not has_last and not has_days:
        return {'keep': ids, 'prune': []}        # no policy → keep everything

    keep = {ids[-1]}                             # always keep the newest scan
    if has_last:
        keep.update(ids[-keep_last:])
    if has_days:
        cutoff = (now or datetime.now()) - timedelta(days=keep_days)
        for s in entries:
            ts = _scan_dt(s)
            if ts is not None and ts >= cutoff:
                keep.add(str(s['id']))

    already = {str(s['id']) for s in entries if s.get('artifacts_pruned')}
    prune = [i for i in ids if i not in keep and i not in already]
    return {'keep': [i for i in ids if i in keep], 'prune': prune}


def _dir_size(path) -> int:
    total = 0
    for p in path.rglob('*'):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def apply_retention(project, plan: Dict[str, List[str]]) -> Dict:
    """Delete the planned scans' artifact directories and mark their metadata
    entries ``artifacts_pruned`` (idempotent; index entry + history snapshot kept).

    Read-modify-write of metadata composes with ``record_scan`` (both load the
    whole metadata and write it back, preserving each other's keys). Returns
    ``{'pruned': [ids], 'freed_bytes': int, 'missing': [ids]}``."""
    prune = [str(i) for i in (plan or {}).get('prune', []) if i]
    if not prune:
        return {'pruned': [], 'freed_bytes': 0, 'missing': []}

    pruned: List[str] = []
    missing: List[str] = []
    freed = 0
    for sid in prune:
        scan_dir = project.root / 'scans' / sid
        if scan_dir.is_dir():
            freed += _dir_size(scan_dir)
            shutil.rmtree(scan_dir, ignore_errors=True)
            pruned.append(sid)
        else:
            missing.append(sid)

    if pruned:
        pruned_set = set(pruned)
        meta = project.load_metadata()
        changed = False
        for entry in meta.get('scans', []):
            if (isinstance(entry, dict) and str(entry.get('id')) in pruned_set
                    and not entry.get('artifacts_pruned')):
                entry['artifacts_pruned'] = True
                changed = True
        if changed:
            meta['updated_at'] = datetime.now().isoformat(timespec='seconds')
            project._write_metadata(meta)
    return {'pruned': pruned, 'freed_bytes': freed, 'missing': missing}


def policy_from_settings(settings: Optional[Dict] = None) -> Dict:
    """The active retention policy from ``settings.json`` (``retention`` block).

    ``{'enabled': bool, 'keep_last': int, 'keep_days': int}`` — disabled by
    default, so callers can gate auto-pruning on ``enabled``."""
    if settings is None:
        from core.config import load_settings
        settings = load_settings()
    cfg = settings.get('retention') if isinstance(settings, dict) else None
    cfg = cfg if isinstance(cfg, dict) else {}
    return {
        'enabled': bool(cfg.get('enabled', False)),
        'keep_last': int(cfg.get('keep_last') or 0),
        'keep_days': int(cfg.get('keep_days') or 0),
    }


def prune_project(project, *, keep_last: Optional[int] = None,
                  keep_days: Optional[int] = None,
                  now: Optional[datetime] = None) -> Dict:
    """Plan + apply in one call. Returns the :func:`apply_retention` result."""
    plan = plan_retention(project, keep_last=keep_last, keep_days=keep_days, now=now)
    return apply_retention(project, plan)
