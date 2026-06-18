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

from core.project import project_slug
from core.scan_diff import write_diff_report

# Supported cadences. Monthly is calendar-aware (see ``_add_month``), the others
# are plain spans.
INTERVALS = ('daily', 'weekly', 'monthly')
_SPANS = {'daily': timedelta(days=1), 'weekly': timedelta(days=7)}


def default_monitor_options() -> Dict:
    """Default per-job scan options (what a monitored scan runs).

    Single source for the monitoring scan profile — mirrors the previous
    hard-coded ``subdomains + certificate`` run so existing schedules behave
    identically, and is the shape ``_build_run_fn`` maps onto ``CollectionRunner``
    keyword arguments. The GUI reuses it when enabling monitoring."""
    return {
        'profile': 'chrome_windows', 'max_pages': 20,
        'subdomains': True, 'certificate': True,
        'nuclei': False, 'katana': False, 'dns': False,
        'screenshots': False, 'llm': False,
    }


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
                  enabled: bool = True, options: Optional[Dict] = None) -> Dict:
    """A fresh schedule dict. The first run is scheduled one interval out, so
    enabling monitoring does not immediately kick off a heavy collection.

    ``options`` is the per-job scan profile (defaults to
    :func:`default_monitor_options`); ``last_status`` tracks the outcome of the
    most recent run (``ok`` / ``failed`` / ``None``)."""
    if interval not in INTERVALS:
        raise ValueError(f'unknown interval: {interval!r} (use {INTERVALS})')
    now = now or datetime.now()
    return {
        'enabled': enabled,
        'interval': interval,
        'options': options or default_monitor_options(),
        'created_at': now.isoformat(timespec='seconds'),
        'last_run': None,
        'last_scan_id': None,
        'last_status': None,
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


# ── schedule management (one source of truth for CLI / web / GUI) ─────────────

def enable(store, url: str, interval: str,
           options: Optional[Dict] = None) -> Dict:
    """Turn monitoring on for ``url`` at ``interval`` (creates the project).

    ``options`` is the per-job scan profile (defaults applied in make_schedule)."""
    project = store.get_or_create(url)
    sched = make_schedule(interval, options=options)
    project.set_monitor(sched)
    return {'slug': project.slug, 'url': url, 'schedule': sched}


def disable(store, url: str) -> Dict:
    """Turn monitoring off for ``url`` (keeps the schedule, flips enabled off)."""
    project = store.get(project_slug(url))
    if project is None:
        return {'error': f'no project for {url}'}
    mon = project.get_monitor()
    if not mon:
        return {'error': f'{project.slug} is not monitored'}
    mon['enabled'] = False
    project.set_monitor(mon)
    return {'slug': project.slug, 'disabled': True}


def status(store) -> List[Dict]:
    """Every monitored project's schedule, newest-updated first (for display)."""
    rows: List[Dict] = []
    for meta in store.list_projects():
        mon = meta.get('monitor')
        if not isinstance(mon, dict):
            continue
        rows.append({
            'slug': meta.get('slug'), 'url': meta.get('url'),
            'enabled': mon.get('enabled'), 'interval': mon.get('interval'),
            'last_run': mon.get('last_run'), 'next_run': mon.get('next_run'),
            'last_status': mon.get('last_status'), 'options': mon.get('options'),
        })
    return rows


def format_event(ev: Dict) -> str:
    """Human line for a monitor run event — shared by the web console feed and
    the in-app scheduler indicator, so the two never render it differently."""
    slug = ev.get('slug', '')
    kind = ev.get('type')
    if kind == 'scan_start':
        return f'[monitor] {slug}: scan start'
    if kind == 'diff':
        return f'[monitor] {slug}: {ev.get("line", "")}'
    if kind == 'scan_done':
        line = ev.get('diff_line')
        return (f'[monitor] {slug}: done {ev.get("scan_id", "")}'
                + (f' · {line}' if line else ' (first scan)'))
    if kind in ('error', 'diff_error'):
        return f'[monitor] {slug}: {kind}: {ev.get("error", "")}'
    if kind == 'alerts':
        # Carries alerts/sent/reason/alert_kind from the dispatchers; the generic
        # fallthrough would drop the count and channel kind (diff / sla / secret /
        # finding), so render them.
        akind = ev.get('alert_kind')
        label = f'alerts ({akind})' if akind else 'alerts'
        reason = ev.get('reason')
        suffix = f' · {reason}' if reason else ''
        return (f'[monitor] {slug}: {ev.get("alerts", 0)} {label}, '
                f'{ev.get("sent", 0)} sent{suffix}')
    return f'[monitor] {slug}: {kind}'


# ── run engine (heavy step injectable) ────────────────────────────────────────

def _build_run_fn(base: str, options: Optional[Dict] = None) -> Callable[[str], Dict]:
    """Build the real collection runner bound to ``base`` and a job's ``options``.

    Imported lazily so the pure logic above (and its tests) never pull in the
    full collection pipeline. ``options`` (a per-job scan profile, defaults from
    :func:`default_monitor_options`) maps onto ``CollectionRunner`` kwargs, so
    monitoring runs whatever the user selected when enabling it."""
    from core.collection_runner import CollectionRunner

    opts = {**default_monitor_options(), **(options or {})}

    def run(url: str) -> Dict:
        runner = CollectionRunner(
            profile=opts.get('profile', 'chrome_windows'),
            max_pages=opts.get('max_pages', 20),
            cookies=opts.get('cookies'),
            capture_delay=opts.get('capture_delay', 0.5),
            subdomains=opts.get('subdomains', True),
            certificate=opts.get('certificate', True),
            nuclei=opts.get('nuclei', False),
            katana=opts.get('katana', False),
            dns=opts.get('dns', False),
            screenshots=opts.get('screenshots', False),
            llm=opts.get('llm', False),
            llm_model=opts.get('llm_model'),
            openapi=opts.get('openapi', False),
            historical=opts.get('historical', False),
            emails=opts.get('emails', False),
            employees=opts.get('employees', False),
            ct=opts.get('ct', False),
            asn_intel=opts.get('asn_intel', False),
            osv=opts.get('osv', False),
            security=opts.get('security', False),
        )
        return runner.run(url, base)

    return run


def run_project(project, run_fn: Callable[[str], Dict],
                now: Optional[datetime] = None,
                on_event: Optional[Callable[[Dict], None]] = None,
                alert_config: Optional[Dict] = None) -> Dict:
    """Run one monitored project's scan + auto-diff and advance its schedule.

    ``run_fn(url)`` performs the Full Collection and records the new scan into
    the project (the real one does; tests inject a fake). Returns a summary
    ``{slug, url, scan_id, prev_scan_id, diff_line, diff_html, status, error}``.
    When ``alert_config`` is set (Alert Center, #9), alertable changes in the
    auto-diff are dispatched and summarized under ``alerts``.
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
                    'diff_html': None, 'alerts': None, 'sla_alerts': None,
                    'secret_alerts': None, 'finding_alerts': None,
                    'status': 'Success', 'error': None}
    emit('scan_start', url=url, prev_scan_id=prev_id)
    try:
        report = run_fn(url)
    except Exception as e:   # noqa: BLE001 — one project must not sink the loop
        result['status'] = 'Error'
        result['error'] = str(e)
        emit('error', error=str(e))
        # Record the failure and roll the schedule forward, so a persistently
        # broken target is retried next interval rather than every tick.
        _advance_schedule(project, None, now, status='failed')
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
            # Alert Center (#9): dispatch alertable changes from this diff.
            if alert_config:
                result['alerts'] = _dispatch_alerts(slug, out['diff'],
                                                    alert_config, emit)
        except Exception as e:   # noqa: BLE001 — a failed diff must not fail the run
            result['error'] = f'diff failed: {e}'
            emit('diff_error', error=str(e))

    # Finding-store-based alert channels (Alert Center): the triggers with no Scan
    # Diff representation, so they are checked every successful run independent of the
    # diff — an SLA deadline slips by time, and audit-only secrets / generic vuln
    # findings have no diff section. One-shot per finding via the store's markers.
    if alert_config and result['status'] == 'Success':
        from core import alerts
        result['sla_alerts'] = _dispatch_finding_based_alerts(
            project, slug, alert_config, emit,
            collect=alerts.collect_sla_alerts, notify=alerts.notify_sla, kind='sla')
        result['secret_alerts'] = _dispatch_finding_based_alerts(
            project, slug, alert_config, emit,
            collect=alerts.collect_secret_alerts, notify=alerts.notify_secret,
            kind='secret')
        result['finding_alerts'] = _dispatch_finding_based_alerts(
            project, slug, alert_config, emit,
            collect=alerts.collect_finding_alerts, notify=alerts.notify_findings,
            kind='finding')

    last_status = 'ok' if result['status'] == 'Success' else 'failed'
    _advance_schedule(project, new_id, now, status=last_status)
    emit('scan_done', scan_id=new_id, diff_line=result['diff_line'])
    return result


def _dispatch_alerts(slug: str, diff: Dict, alert_config: Dict, emit) -> Dict:
    """Send alerts for a diff (lazy import keeps monitor's network surface
    opt-in: core.alerts is only pulled in when alerts are actually configured)."""
    from core import alerts
    summary = alerts.notify(alert_config, slug, diff)
    if summary.get('alerts'):
        emit('alerts', alerts=summary['alerts'], sent=summary.get('sent', 0),
             reason=summary.get('reason'))
    return summary


def _dispatch_finding_based_alerts(project, slug: str, alert_config: Dict, emit, *,
                                   collect, notify, kind: str) -> Optional[Dict]:
    """Dispatch a one-shot, finding-store-based alert channel (SLA breach / audit-only
    secret / generic finding — the triggers with no Scan Diff representation). ``collect``
    pulls the new, deduped events from the store; ``notify`` sends them. Best-effort: a
    failure here never affects the scan/diff result. Returns the send summary, or
    ``None`` when nothing was newly found."""
    try:
        from core.findings_store import FindingsStore
        events = collect(FindingsStore(), project.slug)
        if not events:
            return None
        summary = notify(alert_config, slug, events)
        if summary.get('alerts'):
            emit('alerts', alerts=summary['alerts'], sent=summary.get('sent', 0),
                 reason=summary.get('reason'), alert_kind=kind)
        return summary
    except Exception:   # noqa: BLE001 — alerting must never sink a monitor run
        return None


def _advance_schedule(project, scan_id: Optional[str], now: datetime,
                      status: Optional[str] = None) -> None:
    """Stamp last_run/last_scan_id (+ last_status) and roll next_run forward."""
    mon = project.get_monitor()
    if not mon:
        return
    mon['last_run'] = now.isoformat(timespec='seconds')
    mon['last_scan_id'] = scan_id
    if status is not None:
        mon['last_status'] = status
    interval = mon.get('interval', 'daily')
    try:
        mon['next_run'] = compute_next_run(interval, now).isoformat(timespec='seconds')
    except ValueError:
        mon['next_run'] = compute_next_run('daily', now).isoformat(timespec='seconds')
    project.set_monitor(mon)


def run_due(store, now: Optional[datetime] = None,
            run_fn: Optional[Callable[[str], Dict]] = None,
            on_event: Optional[Callable[[Dict], None]] = None,
            alert_config: Optional[Dict] = None) -> List[Dict]:
    """Run every project in ``store`` whose schedule is enabled and due.

    ``run_fn`` is the heavy collection step; when omitted the real pipeline is
    built per project from its stored ``options`` (bound to the store's base).
    ``alert_config`` (Alert Center, #9) is passed through so each diff can fire
    notifications. Returns one ``run_project`` summary per project that ran
    (empty when nothing is due)."""
    now = now or datetime.now()
    base = str(store.root.parent)
    summaries: List[Dict] = []
    for meta in store.list_projects():
        slug = meta.get('slug')
        project = store.get(slug) if slug else None
        if project is None:
            continue
        mon = project.get_monitor()
        if is_due(mon, now):
            # Honour the job's own scan profile; an injected run_fn (tests) wins.
            rf = run_fn or _build_run_fn(base, (mon or {}).get('options'))
            summaries.append(run_project(project, rf, now=now,
                                         on_event=on_event,
                                         alert_config=alert_config))
    return summaries


# ── scheduler (the only timing/threading part) ────────────────────────────────

class MonitorScheduler:
    """Background loop that periodically runs every due project.

    Thin by design (I5): every check delegates to the pure ``run_due``. Start it
    once; it wakes every ``check_interval`` seconds and stops promptly on
    ``stop()`` (it waits on an Event, so there is no shutdown lag)."""

    def __init__(self, store, check_interval: float = 3600.0,
                 run_fn: Optional[Callable[[str], Dict]] = None,
                 on_event: Optional[Callable[[Dict], None]] = None,
                 alert_config: Optional[Dict] = None):
        self.store = store
        self.check_interval = check_interval
        self.run_fn = run_fn
        self.on_event = on_event
        self.alert_config = alert_config
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def tick(self, now: Optional[datetime] = None) -> List[Dict]:
        """One check pass — public so callers/tests can trigger it directly."""
        return run_due(self.store, now=now, run_fn=self.run_fn,
                       on_event=self.on_event, alert_config=self.alert_config)

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
