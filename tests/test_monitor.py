"""Tests for Continuous Monitoring (core/monitor.py, roadmap Phase 8).

The pure scheduling logic and the run engine are tested without any network:
the heavy collection step is injected as a fake that writes a scan the way the
real CollectionRunner does.
"""

import json
from datetime import datetime

import pytest

from core import monitor
from core.project import ProjectStore


# ── pure scheduling logic ─────────────────────────────────────────────────────

def test_compute_next_run_daily_and_weekly():
    base = datetime(2026, 6, 13, 9, 0, 0)
    assert monitor.compute_next_run('daily', base) == datetime(2026, 6, 14, 9, 0, 0)
    assert monitor.compute_next_run('weekly', base) == datetime(2026, 6, 20, 9, 0, 0)


def test_compute_next_run_monthly_simple():
    assert monitor.compute_next_run('monthly', datetime(2026, 1, 15)) \
        == datetime(2026, 2, 15)


def test_compute_next_run_monthly_clamps_day():
    # Jan 31 -> Feb 28 (2026 is not a leap year).
    assert monitor.compute_next_run('monthly', datetime(2026, 1, 31)) \
        == datetime(2026, 2, 28)
    # Dec rolls the year over.
    assert monitor.compute_next_run('monthly', datetime(2026, 12, 10)) \
        == datetime(2027, 1, 10)


def test_compute_next_run_rejects_bad_interval():
    with pytest.raises(ValueError):
        monitor.compute_next_run('hourly', datetime(2026, 6, 13))


def test_make_schedule_first_run_is_one_interval_out():
    now = datetime(2026, 6, 13, 9, 0, 0)
    sched = monitor.make_schedule('daily', now=now)
    assert sched['enabled'] is True and sched['interval'] == 'daily'
    assert sched['last_run'] is None and sched['last_scan_id'] is None
    assert sched['next_run'] == '2026-06-14T09:00:00'


def test_is_due_logic():
    now = datetime(2026, 6, 13, 12, 0, 0)
    assert monitor.is_due(None, now) is False
    assert monitor.is_due({'enabled': False, 'next_run': None}, now) is False
    # enabled + no next_run -> due (run once)
    assert monitor.is_due({'enabled': True, 'next_run': None}, now) is True
    # next_run in the past -> due; in the future -> not due
    assert monitor.is_due({'enabled': True,
                           'next_run': '2026-06-13T11:00:00'}, now) is True
    assert monitor.is_due({'enabled': True,
                           'next_run': '2026-06-13T13:00:00'}, now) is False
    # unparseable next_run -> due (fail safe)
    assert monitor.is_due({'enabled': True, 'next_run': 'garbage'}, now) is True


# ── per-job options + last_status (T3.1) ──────────────────────────────────────

def test_make_schedule_carries_options_and_last_status():
    s = monitor.make_schedule('daily', now=datetime(2026, 6, 13))
    assert s['last_status'] is None
    assert s['options'] == monitor.default_monitor_options()
    # explicit options are stored verbatim (defaults merged only at run time)
    s2 = monitor.make_schedule('daily', now=datetime(2026, 6, 13),
                               options={'nuclei': True})
    assert s2['options'] == {'nuclei': True}


def test_default_monitor_options_preserves_legacy_profile():
    opts = monitor.default_monitor_options()
    assert opts['subdomains'] is True and opts['certificate'] is True
    assert opts['nuclei'] is False and opts['max_pages'] == 20


def test_build_run_fn_maps_options_to_runner(monkeypatch):
    captured = {}

    class FakeRunner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self, url, base):
            return {'url': url, 'base': base, 'status': 'Success'}

    monkeypatch.setattr('core.collection_runner.CollectionRunner', FakeRunner)
    rf = monitor._build_run_fn('/base', {'nuclei': True, 'subdomains': False,
                                         'osv': True, 'security': True,
                                         'bbot': True,
                                         'profile': 'firefox_windows'})
    out = rf('https://x.com')
    assert out['base'] == '/base'
    assert captured['nuclei'] is True and captured['subdomains'] is False
    assert captured['osv'] is True            # opt-in OSV correlation maps through
    assert captured['security'] is True       # opt-in security audit maps through
    assert captured['bbot'] is True           # opt-in BBOT recon maps through
    assert captured['profile'] == 'firefox_windows'
    assert captured['certificate'] is True        # default preserved on merge


def test_build_run_fn_documents_maps_through(monkeypatch):
    captured = {}

    class FakeRunner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self, url, base):
            return {'status': 'Success'}

    monkeypatch.setattr('core.collection_runner.CollectionRunner', FakeRunner)
    monitor._build_run_fn('/base', {'documents': True})('https://x.com')
    assert captured['documents'] is True
    monitor._build_run_fn('/base', {})('https://x.com')
    assert captured['documents'] is False             # off unless selected


def test_build_run_fn_bbot_defaults_off(monkeypatch):
    captured = {}

    class FakeRunner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self, url, base):
            return {'status': 'Success'}

    monkeypatch.setattr('core.collection_runner.CollectionRunner', FakeRunner)
    monitor._build_run_fn('/base', {})('https://x.com')
    assert captured['bbot'] is False              # off unless explicitly selected


def test_format_event_kinds():
    assert 'scan start' in monitor.format_event({'type': 'scan_start', 'slug': 'x'})
    assert 'first scan' in monitor.format_event(
        {'type': 'scan_done', 'slug': 'x', 'scan_id': '1'})
    done = monitor.format_event(
        {'type': 'scan_done', 'slug': 'x', 'scan_id': '2', 'diff_line': 'd'})
    assert 'd' in done and 'first scan' not in done
    assert 'error' in monitor.format_event(
        {'type': 'error', 'slug': 'x', 'error': 'boom'})
    integrity = monitor.format_event({
        'type': 'evidence_integrity',
        'slug': 'x',
        'warnings': ['scan s1: evidence integrity missing_manifest'],
    })
    assert 'evidence integrity warning' in integrity and 'missing_manifest' in integrity
    # Alert events render the count / sent / channel kind (not a bare "alerts").
    diff_al = monitor.format_event(
        {'type': 'alerts', 'slug': 'x', 'alerts': 3, 'sent': 2})
    assert '3 alerts' in diff_al and '2 sent' in diff_al
    secret_al = monitor.format_event(
        {'type': 'alerts', 'slug': 'x', 'alerts': 1, 'sent': 0,
         'alert_kind': 'secret', 'reason': 'no channels'})
    assert 'alerts (secret)' in secret_al and 'no channels' in secret_al


# ── Project schedule persistence ──────────────────────────────────────────────

def test_project_get_set_clear_monitor(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    assert project.get_monitor() is None
    sched = monitor.make_schedule('weekly', now=datetime(2026, 6, 13))
    project.set_monitor(sched)
    assert project.get_monitor()['interval'] == 'weekly'
    project.set_monitor(None)
    assert project.get_monitor() is None


def test_monitor_survives_record_scan(tmp_path):
    # The schedule must coexist with the scan index (both rewrite metadata.json).
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    sd = project.start_scan('20260613_010000')
    project.record_scan(sd, {'url': 'https://x.com', 'status': 'Success',
                             'executive_summary': {'risk_level': 'Low'}})
    assert project.get_monitor()['interval'] == 'daily'   # not clobbered
    assert len(project.scans()) == 1


# ── schedule management helpers (shared by CLI / web / GUI) ───────────────────

def test_enable_creates_project_and_schedule(tmp_path):
    store = ProjectStore(tmp_path)
    out = monitor.enable(store, 'https://example.com', 'weekly')
    assert out['slug'] == 'example.com'
    assert out['schedule']['interval'] == 'weekly'
    assert store.get('example.com').get_monitor()['enabled'] is True


def test_disable_flips_enabled_off(tmp_path):
    store = ProjectStore(tmp_path)
    monitor.enable(store, 'https://example.com', 'daily')
    out = monitor.disable(store, 'https://example.com')
    assert out['disabled'] is True
    assert store.get('example.com').get_monitor()['enabled'] is False


def test_disable_unknown_or_unmonitored(tmp_path):
    store = ProjectStore(tmp_path)
    assert 'error' in monitor.disable(store, 'https://nope.com')
    store.get_or_create('https://plain.com')   # exists but never monitored
    assert 'error' in monitor.disable(store, 'https://plain.com')


def test_status_lists_only_monitored(tmp_path):
    store = ProjectStore(tmp_path)
    monitor.enable(store, 'https://watched.com', 'monthly')
    store.get_or_create('https://unwatched.com')
    rows = monitor.status(store)
    assert [r['slug'] for r in rows] == ['watched.com']
    assert rows[0]['interval'] == 'monthly' and rows[0]['enabled'] is True


def test_enable_passes_options_through(tmp_path):
    store = ProjectStore(tmp_path)
    monitor.enable(store, 'https://x.com', 'daily', options={'dns': True})
    assert store.get('x.com').get_monitor()['options'] == {'dns': True}


def test_status_includes_last_status_and_options(tmp_path):
    store = ProjectStore(tmp_path)
    monitor.enable(store, 'https://w.com', 'daily', options={'dns': True})
    row = monitor.status(store)[0]
    assert row['last_status'] is None and row['options'] == {'dns': True}


# ── run engine with an injected (offline) collection step ─────────────────────

def _fake_run_fn(project, pages_by_scan):
    """Return a run_fn that records a new scan into ``project`` like the real
    CollectionRunner does, with a controllable site_map so the diff has signal.
    Each call uses the next id/pages from ``pages_by_scan``."""
    state = {'i': 0}

    def run(url):
        sid, pages = pages_by_scan[state['i']]
        state['i'] += 1
        sd = project.start_scan(sid)
        report = {
            'url': url, 'status': 'Success', 'scan_id': sid,
            'phases': {'capture': {'status': 'Success', 'data': {
                'site_map': [{'url': p, 'status': 200} for p in pages]}}},
            'executive_summary': {'risk_level': 'Low', 'risk_100': 1,
                                  'metrics': {'risk_100': 1}},
        }
        (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        project.record_scan(sd, report)
        return report

    return run


def test_run_project_first_run_has_no_diff(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    run_fn = _fake_run_fn(project, [('20260613_010000', ['/a'])])
    out = monitor.run_project(project, run_fn, now=datetime(2026, 6, 13, 10, 0))
    assert out['status'] == 'Success'
    assert out['scan_id'] == '20260613_010000'
    assert out['prev_scan_id'] is None
    assert out['diff_line'] is None          # nothing to diff against yet
    # schedule advanced to the next day
    assert project.get_monitor()['last_scan_id'] == '20260613_010000'
    assert project.get_monitor()['next_run'] == '2026-06-14T10:00:00'


def test_run_project_second_run_writes_auto_diff(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    run_fn = _fake_run_fn(project, [('20260613_010000', ['/a']),
                                    ('20260614_010000', ['/a', '/b'])])
    monitor.run_project(project, run_fn, now=datetime(2026, 6, 13, 10, 0))
    out = monitor.run_project(project, run_fn, now=datetime(2026, 6, 14, 10, 0))
    assert out['prev_scan_id'] == '20260613_010000'
    assert out['scan_id'] == '20260614_010000'
    assert out['diff_html'] and out['diff_html'].endswith('.html')
    # the diff saw the added page
    assert 'Страницы' in out['diff_line']


def test_run_project_attaches_evidence_integrity_warning(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    events = []
    run_fn = _fake_run_fn(project, [('20260613_010000', ['/a'])])

    out = monitor.run_project(project, run_fn, now=datetime(2026, 6, 13, 10, 0),
                              on_event=events.append)

    assert out['status'] == 'Success'
    assert out['evidence_integrity']['ok'] is False
    assert out['evidence_integrity']['warnings']
    assert any(e['type'] == 'evidence_integrity' for e in events)


def test_finding_alert_failure_is_reported(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    events = []

    def collect(store, slug):
        raise RuntimeError('store down')

    def emit(kind, **kw):
        events.append({'type': kind, 'slug': 'x.com', **kw})

    out = monitor._dispatch_finding_based_alerts(
        project, 'x.com', {'enabled': True}, emit,
        collect=collect, notify=lambda cfg, slug, ev: {}, kind='sla')

    assert out['error'] == 'store down'
    assert out['reason'] == 'sla alert failed'
    assert events == [{'type': 'alert_error', 'slug': 'x.com',
                       'alert_kind': 'sla', 'error': 'store down'}]
    assert 'store down' in monitor.format_event(events[0])


def test_run_project_records_last_status_ok_then_failed(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    run_fn = _fake_run_fn(project, [('20260613_010000', ['/a'])])
    monitor.run_project(project, run_fn, now=datetime(2026, 6, 13, 10, 0))
    assert project.get_monitor()['last_status'] == 'ok'

    def boom(url):
        raise RuntimeError('collection blew up')

    monitor.run_project(project, boom, now=datetime(2026, 6, 14, 10, 0))
    mon = project.get_monitor()
    assert mon['last_status'] == 'failed'
    # a failure still rolls the schedule forward (no tight retry loop)
    assert mon['next_run'] == '2026-06-15T10:00:00'


def test_run_due_builds_run_fn_from_each_project_options(tmp_path, monkeypatch):
    store = ProjectStore(tmp_path)
    monitor.enable(store, 'https://a.com', 'daily', options={'nuclei': True})
    a = store.get('a.com')
    m = a.get_monitor(); m['next_run'] = '2000-01-01T00:00:00'; a.set_monitor(m)

    seen = {}

    def fake_build(base, options):
        def run(url):
            from core.project import project_slug
            proj = store.get(project_slug(url))
            sid = '20260613_120000'
            sd = proj.start_scan(sid)
            report = {'url': url, 'status': 'Success', 'scan_id': sid,
                      'executive_summary': {'risk_level': 'Low'}}
            (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
            proj.record_scan(sd, report)
            seen['options'] = options
            return report
        return run

    monkeypatch.setattr(monitor, '_build_run_fn', fake_build)
    monitor.run_due(store, now=datetime(2026, 6, 13, 12, 0))
    assert seen['options'] == {'nuclei': True}      # the job's own profile


def test_run_due_runs_only_enabled_and_due(tmp_path):
    store = ProjectStore(tmp_path)
    due = store.get_or_create('https://due.com')
    due.set_monitor({'enabled': True, 'interval': 'daily',
                     'next_run': '2026-06-13T00:00:00'})
    future = store.get_or_create('https://future.com')
    future.set_monitor({'enabled': True, 'interval': 'daily',
                        'next_run': '2099-01-01T00:00:00'})
    off = store.get_or_create('https://off.com')
    off.set_monitor({'enabled': False, 'interval': 'daily', 'next_run': None})
    store.get_or_create('https://none.com')   # no schedule at all

    ran = []

    def run_fn(url):
        sid = '20260613_120000'
        # find which project this url belongs to and record into it
        from core.project import project_slug
        proj = store.get(project_slug(url))
        sd = proj.start_scan(sid)
        report = {'url': url, 'status': 'Success', 'scan_id': sid,
                  'executive_summary': {'risk_level': 'Low'}}
        (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        proj.record_scan(sd, report)
        ran.append(url)
        return report

    summaries = monitor.run_due(store, now=datetime(2026, 6, 13, 12, 0),
                                run_fn=run_fn)
    assert ran == ['https://due.com']
    assert [s['slug'] for s in summaries] == ['due.com']


def test_run_project_fires_alerts_on_diff(tmp_path, monkeypatch):
    # Second scan adds a page-less diff with a new subdomain → an alert.
    from core import alerts
    sent = []
    monkeypatch.setattr(alerts, '_http_post',
                        lambda *a, **k: (sent.append(1), 200)[1])

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))

    def run_fn_factory(subs_by_scan):
        state = {'i': 0}

        def run(url):
            sid = ['20260613_010000', '20260614_010000'][state['i']]
            subs = subs_by_scan[state['i']]
            state['i'] += 1
            sd = project.start_scan(sid)
            report = {
                'url': url, 'status': 'Success', 'scan_id': sid,
                'phases': {'subdomains': {'status': 'Success', 'data': {
                    'results': [{'subdomain': s} for s in subs]}}},
                'executive_summary': {'risk_level': 'Low', 'risk_100': 1,
                                      'metrics': {'risk_100': 1}},
            }
            (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
            project.record_scan(sd, report)
            return report
        return run

    run_fn = run_fn_factory([['a.x.com'], ['a.x.com', 'b.x.com']])
    alert_config = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}

    monitor.run_project(project, run_fn, now=datetime(2026, 6, 13, 10, 0),
                        alert_config=alert_config)
    out = monitor.run_project(project, run_fn, now=datetime(2026, 6, 14, 10, 0),
                              alert_config=alert_config)
    assert out['alerts']['alerts'] == 1      # one new subdomain
    assert out['alerts']['sent'] == 1
    assert sent == [1]


def test_run_project_fires_sla_breach_alert_once(tmp_path, monkeypatch):
    # An active finding past its SLA deadline fires an alert on the run that first
    # observes the breach (time-triggered, diff-independent) — then never again.
    from core import alerts
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    FindingsStore().upsert(project.slug, {
        'id': fingerprint('vuln', 'https', 'https://x.com/'),
        'category': 'vuln', 'rule_id': 'https', 'title': 'Plain HTTP',
        'severity': 'high', 'evidence': None}, now='2020-01-01T00:00:00')
    alert_config = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}

    run1 = _fake_run_fn(project, [('20260613_010000', ['/a'])])
    out1 = monitor.run_project(project, run1, now=datetime(2026, 6, 13, 10, 0),
                               alert_config=alert_config)
    assert out1['sla_alerts'] and out1['sla_alerts']['alerts'] == 1
    assert out1['sla_alerts']['sent'] == 1

    run2 = _fake_run_fn(project, [('20260614_010000', ['/a'])])
    out2 = monitor.run_project(project, run2, now=datetime(2026, 6, 14, 10, 0),
                               alert_config=alert_config)
    assert out2['sla_alerts'] is None        # already alerted → nothing new


def test_run_project_fires_audit_secret_alert_once(tmp_path, monkeypatch):
    # An audit-only secret finding (no Scan Diff representation) fires a finding-based
    # alert on the run that first sees it (diff-independent) — then never again.
    from core import alerts
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    FindingsStore().upsert(project.slug, {
        'id': fingerprint('secret', 'AWS Access Key', 'https://x.com/app.js'),
        'category': 'secret', 'rule_id': '',
        'title': 'Leaked secret: AWS Access Key', 'severity': 'high',
        'evidence': {'source': 'secret-audit', 'location': 'https://x.com/app.js'}})
    alert_config = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}

    run1 = _fake_run_fn(project, [('20260613_010000', ['/a'])])
    out1 = monitor.run_project(project, run1, now=datetime(2026, 6, 13, 10, 0),
                               alert_config=alert_config)
    assert out1['secret_alerts'] and out1['secret_alerts']['alerts'] == 1
    assert out1['secret_alerts']['sent'] == 1

    run2 = _fake_run_fn(project, [('20260614_010000', ['/a'])])
    out2 = monitor.run_project(project, run2, now=datetime(2026, 6, 14, 10, 0),
                               alert_config=alert_config)
    assert out2['secret_alerts'] is None        # already alerted → nothing new


def test_run_project_fires_generic_finding_alert_once(tmp_path, monkeypatch):
    # A new high/critical generic vuln finding (no dedicated diff alert) fires the
    # finding-based channel on the run that first sees it — then never again.
    from core import alerts
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    FindingsStore().upsert(project.slug, {
        'id': fingerprint('vuln', 'sqli', 'https://x.com/q'),
        'category': 'vuln', 'rule_id': 'sqli', 'title': 'SQL Injection',
        'severity': 'High', 'evidence': {'source': 'nuclei'}})
    alert_config = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}

    run1 = _fake_run_fn(project, [('20260613_010000', ['/a'])])
    out1 = monitor.run_project(project, run1, now=datetime(2026, 6, 13, 10, 0),
                               alert_config=alert_config)
    assert out1['finding_alerts'] and out1['finding_alerts']['alerts'] == 1
    assert out1['finding_alerts']['sent'] == 1

    run2 = _fake_run_fn(project, [('20260614_010000', ['/a'])])
    out2 = monitor.run_project(project, run2, now=datetime(2026, 6, 14, 10, 0),
                               alert_config=alert_config)
    assert out2['finding_alerts'] is None        # already alerted → nothing new


def test_run_project_survives_failing_run_fn(tmp_path):
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))

    def boom(url):
        raise RuntimeError('collection blew up')

    out = monitor.run_project(project, boom, now=datetime(2026, 6, 13, 10, 0))
    assert out['status'] == 'Error' and 'blew up' in out['error']


# ── scheduler (thin timing wrapper) ───────────────────────────────────────────

def test_scheduler_tick_delegates_to_run_due(tmp_path):
    store = ProjectStore(tmp_path)
    p = store.get_or_create('https://x.com')
    p.set_monitor({'enabled': True, 'interval': 'daily',
                   'next_run': '2026-06-13T00:00:00'})
    calls = []

    def run_fn(url):
        sid = '20260613_120000'
        from core.project import project_slug
        proj = store.get(project_slug(url))
        sd = proj.start_scan(sid)
        report = {'url': url, 'status': 'Success', 'scan_id': sid,
                  'executive_summary': {'risk_level': 'Low'}}
        (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        proj.record_scan(sd, report)
        calls.append(url)
        return report

    sched = monitor.MonitorScheduler(store, check_interval=999, run_fn=run_fn)
    summaries = sched.tick(now=datetime(2026, 6, 13, 12, 0))
    assert [s['slug'] for s in summaries] == ['x.com']
    assert calls == ['https://x.com']


def test_scheduler_tick_runs_extra_tick_after_sweep(tmp_path):
    store = ProjectStore(tmp_path)
    seen = []
    sched = monitor.MonitorScheduler(
        store, check_interval=999,
        extra_tick=lambda now: seen.append(now))
    sched.tick(now=datetime(2026, 6, 13, 12, 0))
    assert seen == [datetime(2026, 6, 13, 12, 0)]


def test_scheduler_extra_tick_failure_is_reported_not_raised(tmp_path):
    store = ProjectStore(tmp_path)
    events = []

    def boom(now):
        raise RuntimeError("mission tick failed")

    sched = monitor.MonitorScheduler(
        store, check_interval=999, on_event=events.append, extra_tick=boom)
    sched.tick(now=datetime(2026, 6, 13, 12, 0))      # must not raise
    assert any(e.get('type') == 'error' and 'mission tick failed' in e.get('error', '')
               for e in events)


def test_format_event_mission_run():
    line = monitor.format_event({'type': 'mission_run', 'slug': 'shop.com',
                                 'mission_id': 'mission-x', 'run_id': 'msched-1',
                                 'status': 'ok'})
    assert 'mission-x' in line and 'msched-1' in line and 'shop.com' in line


def test_scheduler_start_stop_is_clean():
    from core.project import ProjectStore as _PS
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        sched = monitor.MonitorScheduler(_PS(d), check_interval=999)
        assert sched.running() is False
        sched.start()
        assert sched.running() is True
        sched.stop()
        assert sched.running() is False


def test_run_project_fires_acceptance_expiry_alert_once(tmp_path, monkeypatch):
    # A finding whose risk acceptance has lapsed fires an alert on the run that
    # first observes the expiry (time-triggered, diff-independent) — then not again.
    from core import alerts
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    project.set_monitor(monitor.make_schedule('daily', now=datetime(2026, 6, 13)))
    store = FindingsStore()
    fid = store.upsert(project.slug, {
        'id': fingerprint('vuln', 'https', 'https://x.com/'),
        'category': 'vuln', 'rule_id': 'https', 'title': 'Plain HTTP',
        'severity': 'high', 'evidence': None})['finding']['id']
    store.accept_risk(fid, until='2000-01-01')      # already lapsed
    alert_config = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}

    run1 = _fake_run_fn(project, [('20260613_010000', ['/a'])])
    out1 = monitor.run_project(project, run1, now=datetime(2026, 6, 13, 10, 0),
                               alert_config=alert_config)
    assert out1['acceptance_alerts'] and out1['acceptance_alerts']['alerts'] == 1
    assert out1['acceptance_alerts']['sent'] == 1

    run2 = _fake_run_fn(project, [('20260614_010000', ['/a'])])
    out2 = monitor.run_project(project, run2, now=datetime(2026, 6, 14, 10, 0),
                               alert_config=alert_config)
    assert out2['acceptance_alerts'] is None        # already alerted → nothing new
