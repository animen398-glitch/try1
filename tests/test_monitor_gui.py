"""Continuous Monitoring (#8) — Collection tab UI (headless Qt).

The monitoring section reflects a project's schedule, and the Enable/Disable
buttons drive core.monitor through the same store as Scan Diff.
"""

import json

from core import monitor
from core.project import ProjectStore


def _seed_project(base, slug_url='https://example.com', scans=('20260613_010000',)):
    p = ProjectStore(base).get_or_create(slug_url)
    for sid in scans:
        sd = p.start_scan(sid)
        report = {'url': slug_url, 'status': 'Success', 'scan_id': sid,
                  'executive_summary': {'risk_level': 'Low'}}
        (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        p.record_scan(sd, report)
    return p


def _window(qapp, tmp_path):
    from gui.main_window import MainWindow
    w = MainWindow()
    w.collect_dir.setText(str(tmp_path))   # store points at tmp
    return w


def test_monitor_combo_populates_and_shows_untracked(qapp, tmp_path):
    _seed_project(tmp_path)
    w = _window(qapp, tmp_path)
    w._refresh_monitor_projects()
    assert w.monitor_project.count() == 1
    assert w.monitor_project.currentData() == 'example.com'
    # No schedule yet.
    assert 'Не отслеживается' in w.monitor_status.text()


def test_enable_then_status_reflects_schedule(qapp, tmp_path):
    _seed_project(tmp_path)
    w = _window(qapp, tmp_path)
    w._refresh_monitor_projects()
    # pick weekly and enable
    idx = w.monitor_interval.findData('weekly')
    w.monitor_interval.setCurrentIndex(idx)
    w._enable_monitor()

    mon = ProjectStore(tmp_path).get('example.com').get_monitor()
    assert mon['enabled'] is True and mon['interval'] == 'weekly'
    # status label now shows the enabled schedule
    assert '[вкл]' in w.monitor_status.text() and 'weekly' in w.monitor_status.text()


def test_disable_from_ui(qapp, tmp_path):
    p = _seed_project(tmp_path)
    p.set_monitor(monitor.make_schedule('daily'))
    w = _window(qapp, tmp_path)
    w._refresh_monitor_projects()
    w._disable_monitor()
    assert ProjectStore(tmp_path).get('example.com').get_monitor()['enabled'] is False
    assert '[выкл]' in w.monitor_status.text()


def test_monitor_refresh_tolerates_empty_store(qapp, tmp_path):
    w = _window(qapp, tmp_path / 'empty')
    w._refresh_monitor_projects()       # must not raise
    assert w.monitor_project.count() == 0
    assert 'Не отслеживается' in w.monitor_status.text()
