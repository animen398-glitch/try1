"""core/monitor.py
Continuous Monitoring — keep a target under watch and diff each new scan
against the previous one automatically (roadmap Phase 8).

A *schedule* lives on the project, in ``metadata.json`` under a ``monitor`` key
(``Project.get_monitor`` / ``set_monitor``). It says how often to re-scan
(daily / weekly / monthly) and when the next run is due. The scheduler walks a
``ProjectStore``; for every project whose schedule is enabled and due it:

    1. runs a Full Collection (recording a new timestamped scan), then
    2. if a previous scan exists, writes an offline Scan Diff against it, then
    3. advances ``last_run`` / ``next_run`` on the schedule.

Architectural invariants:
  * I1/I2 — stdlib only, fully offline by itself (the collection it triggers
    does whatever network the user already opted into; monitoring adds none).
  * I3 — the schedule + scan list live in ``metadata.json`` (single source).
  * I4 — all logic is here, so the GUI/CLI stay thin callers.
  * I5 — the *timing/threading* (``MonitorScheduler``) is split from the *pure*
    scheduling logic (``compute_next_run`` / ``is_due``) and from the run engine
    (``run_due``), whose heavy collection step is injectable so tests never
    touch the network.
"""

import threading
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from core.scan_diff import write_diff_report

# Supported cadences. Monthly is calendar-aware (see ``_add_month``), the others
# are plain spans.
INTERVALS = ('daily', 'weekly', 'monthly')
_SPANS = {'daily': timedelta(days=1), 'weekly': timedelta(days=7)}


# ── pure scheduling logic ─────────────────────────────────────────────────────

def _add_month(dt: datetime) -> datetime:
    """``dt`` plus one calendar month, clamping the day to the target month.

    Jan 31 → Feb 28/29, etc. Pure stdlib (no dateutil) so the only dependency
    stays the standard library (I1)."""
    year = dt.year + (dt.month // 12)
    month = dt.month % 12 + 1
    # Last valid day of the target month: day before the 1st of the month after.
    nxt_year = year + (month // 12)
    nxt_month = month % 12 + 1
    last_day = (datetime(nxt_year, nxt_month, 1) - timedelta(days=1)).day
    return dt.replace(year=year, month=month, day=min(dt.day, last_day))


def compute_next_run(interval: str, from_dt: Optional[datetime] = None) -> datetime:
    """When the next scan is due, ``interval`` after ``from_dt`` (default now)."""
    if interval not in INTERVALS:
        raise ValueError(f'unknown interval: {interval!r} (use {INTERVALS})')
    base = from_dt or datetime.now()
    if interval == 'monthly':
        return _add_month(base)
    return base + _SPANS[interval]


def make_schedule(interval: str, now: Optional[datetime] = None,
                  enabled: bool = True) -> Dict:
    """A fresh schedule dict. The first run is scheduled one interval out, so
    enabling monitoring does not immediately kick off a heavy collection."""
    if interval not in INTERVALS:
        raise ValueError(f'unknown interval: {interval!r} (use {INTERVALS})')
    now = now or datetime.now()
    return {
        'enabled': enabled,
        'interval': interval,
        'created_at': now.isoformat(timespec='seconds'),
        'last_run': None,
        'last_scan_id': None,
        'next_run': compute_next_run(interval, now).isoformat(timespec='seconds'),
    }


def is_due(monitor: Optional[Dict], now: Optional[datetime] = None) -> bool:
    """True if an enabled schedule's ``next_run`` has arrived.

    A missing/unparseable ``next_run`` counts as due (run once, then it gets a
    real next_run). A disabled or absent schedule is never due."""
    if not monitor or not monitor.get('enabled'):
        return False
    now = now or datetime.now()
    nxt = monitor.get('next_run')
    if not nxt:
        return True
    try:
        return now >= datetime.fromisoformat(nxt)
    except (ValueError, TypeError):
        return True


# ── run engine (heavy step injectable) ────────────────────────────────────────

def _default_run_fn(base: str) -> Callable[[str], Dict]:
    """Build the real collection runner bound to ``base``.

    Imported lazily so the pure logic above (and its tests) never pull in the
    full collection pipeline. Subdomains + certificate are on so monitoring
    actually surfaces the changes Scan Diff knows how to report."""
    from core.collection_runner import CollectionRunner

    def run(url: str) -> Dict:
        runner = CollectionRunner(max_pages=20, subdomains=True, certificate=True)
        return runner.run(url, base)

    return run


def run_project(project, run_fn: Callable[[str], Dict],
                now: Optional[datetime] = None,
                on_event: Optional[Callable[[Dict], None]] = None) -> Dict:
    """Run one monitored project's scan + auto-diff and advance its schedule.

    ``run_fn(url)`` performs the Full Collection and records the new scan into
    the project (the real one does; tests inject a fake). Returns a summary
    ``{slug, url, scan_id, prev_scan_id, diff_line, diff_html, status, error}``.
    """
    now = now or datetime.now()
    meta = project.load_metadata()
    url = project.url or meta.get('url') or ''
    slug = meta.get('slug') or project.slug

    def emit(kind: str, **kw):
        if on_event:
            on_event({'type': kind, 'slug': slug, **kw})

    # The previous scan id is captured *before* the new run so we can diff
    # against it afterwards.
    prev = project.latest_scan()
    prev_id = prev.get('id') if prev else None

    result: Dict = {'slug': slug, 'url': url, 'scan_id': None,
                    'prev_scan_id': prev_id, 'diff_line': None,
                    'diff_html': None, 'status': 'Success', 'error': None}
    emit('scan_start', url=url, prev_scan_id=prev_id)
    try:
        report = run_fn(url)
    except Exception as e:   # noqa: BLE001 — one project must not sink the loop
        result['status'] = 'Error'
        result['error'] = str(e)
        emit('error', error=str(e))
        return result

    new_id = report.get('scan_id')
    result['scan_id'] = new_id
    result['status'] = report.get('status', 'Success')

    # Auto Scan Diff against the prior scan (skipped on the very first run, or
    # if the runner somehow produced no new scan id).
    if prev_id and new_id and prev_id != new_id:
        try:
            out = write_diff_report(project, prev_id, new_id)
            result['diff_line'] = out['line']
            result['diff_html'] = out['html_path']
            emit('diff', prev_scan_id=prev_id, scan_id=new_id, line=out['line'])
        except Exception as e:   # noqa: BLE001 — a failed diff must not fail the run
            result['error'] = f'diff failed: {e}'
            emit('diff_error', error=str(e))

    _advance_schedule(project, new_id, now)
    emit('scan_done', scan_id=new_id, diff_line=result['diff_line'])
    return result


def _advance_schedule(project, scan_id: Optional[str], now: datetime) -> None:
    """Stamp last_run/last_scan_id and roll next_run forward by one interval."""
    mon = project.get_monitor()
    if not mon:
        return
    mon['last_run'] = now.isoformat(timespec='seconds')
    mon['last_scan_id'] = scan_id
    interval = mon.get('interval', 'daily')
    try:
        mon['next_run'] = compute_next_run(interval, now).isoformat(timespec='seconds')
    except ValueError:
        mon['next_run'] = compute_next_run('daily', now).isoformat(timespec='seconds')
    project.set_monitor(mon)


def run_due(store, now: Optional[datetime] = None,
            run_fn: Optional[Callable[[str], Dict]] = None,
            on_event: Optional[Callable[[Dict], None]] = None) -> List[Dict]:
    """Run every project in ``store`` whose schedule is enabled and due.

    ``run_fn`` is the heavy collection step; when omitted the real pipeline is
    used (bound to the store's base). Returns one ``run_project`` summary per
    project that ran (empty when nothing is due)."""
    now = now or datetime.now()
    run_fn = run_fn or _default_run_fn(str(store.root.parent))
    summaries: List[Dict] = []
    for meta in store.list_projects():
        slug = meta.get('slug')
        project = store.get(slug) if slug else None
        if project is None:
            continue
        if is_due(project.get_monitor(), now):
            summaries.append(run_project(project, run_fn, now=now,
                                         on_event=on_event))
    return summaries


# ── scheduler (the only timing/threading part) ────────────────────────────────

class MonitorScheduler:
    """Background loop that periodically runs every due project.

    Thin by design (I5): every check delegates to the pure ``run_due``. Start it
    once; it wakes every ``check_interval`` seconds and stops promptly on
    ``stop()`` (it waits on an Event, so there is no shutdown lag)."""

    def __init__(self, store, check_interval: float = 3600.0,
                 run_fn: Optional[Callable[[str], Dict]] = None,
                 on_event: Optional[Callable[[Dict], None]] = None):
        self.store = store
        self.check_interval = check_interval
        self.run_fn = run_fn
        self.on_event = on_event
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def tick(self, now: Optional[datetime] = None) -> List[Dict]:
        """One check pass — public so callers/tests can trigger it directly."""
        return run_due(self.store, now=now, run_fn=self.run_fn,
                       on_event=self.on_event)

    def start(self) -> None:
        if self.running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name='MonitorScheduler')
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:   # noqa: BLE001 — the loop must survive a bad pass
                if self.on_event:
                    self.on_event({'type': 'error', 'error': str(e)})
            self._stop.wait(self.check_interval)

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
