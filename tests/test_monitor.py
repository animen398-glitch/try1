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
