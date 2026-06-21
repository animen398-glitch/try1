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


# ── in-app scheduler adapter (T3.2) ───────────────────────────────────────────

def test_inapp_scheduler_starts_and_stops(qapp, tmp_path):
    w = _window(qapp, tmp_path)
    # Point the watcher at an empty store so its immediate tick does no work.
    w.settings['output_dir'] = str(tmp_path / 'empty')
    w.settings['monitor_check_interval'] = 999
    assert w._monitor_running() is False
    assert w.monitor_indicator.text() == ''

    assert w._start_monitor_scheduler() is True
    try:
        assert w._monitor_running() is True
        assert 'Мониторинг' in w.monitor_indicator.text()
        assert w._start_monitor_scheduler() is False        # idempotent
    finally:
        w._stop_monitor_scheduler()
    assert w._monitor_running() is False
    assert w.monitor_indicator.text() == ''


def test_monitor_event_marshals_to_status(qapp, tmp_path):
    w = _window(qapp, tmp_path)
    w._on_monitor_event({'type': 'scan_done', 'slug': 'x.com',
                         'scan_id': '20260613', 'diff_line': '+1 page'})
    assert 'x.com' in w.monitor_status.text()
    assert 'x.com' in w.status_bar.currentMessage()


def test_autostart_starts_scheduler_from_settings(qapp, tmp_path, monkeypatch):
    from core import config
    settings = dict(config.DEFAULT_SETTINGS)
    settings['monitor_autostart'] = True
    settings['output_dir'] = str(tmp_path / 'empty')
    settings['monitor_check_interval'] = 999
    monkeypatch.setattr(config, 'load_settings', lambda: dict(settings))

    from gui.main_window import MainWindow
    w = MainWindow()
    try:
        assert w._monitor_running() is True
        assert 'Мониторинг' in w.monitor_indicator.text()
    finally:
        w._stop_monitor_scheduler()


# ── per-job options + autostart checkbox (T3.4) ───────────────────────────────

def test_collection_options_reflects_checkboxes(qapp, tmp_path):
    w = _window(qapp, tmp_path)
    w.collect_subdomains.setChecked(True)
    w.collect_dns.setChecked(True)
    w.collect_certificate.setChecked(False)
    w.collect_bbot.setChecked(True)
    w.collect_documents.setChecked(True)
    opts = w._collection_options()
    assert opts['subdomains'] is True and opts['dns'] is True
    assert opts['certificate'] is False
    assert opts['bbot'] is True                    # opt-in BBOT reflected
    assert opts['documents'] is True              # opt-in Document Intelligence
    assert 'profile' in opts and 'max_pages' in opts


def test_enable_monitor_stores_selected_options(qapp, tmp_path):
    _seed_project(tmp_path)
    w = _window(qapp, tmp_path)
    w._refresh_monitor_projects()
    w.collect_dns.setChecked(True)
    w.collect_subdomains.setChecked(False)
    w._enable_monitor()
    mon = ProjectStore(tmp_path).get('example.com').get_monitor()
    assert mon['options']['dns'] is True
    assert mon['options']['subdomains'] is False


def test_autostart_checkbox_toggles_scheduler_and_persists(qapp, tmp_path,
                                                           monkeypatch):
    saved = {}
    monkeypatch.setattr('core.config.save_settings',
                        lambda s: (saved.update(s), True)[1])
    w = _window(qapp, tmp_path)
    w.settings['output_dir'] = str(tmp_path / 'empty')   # empty store, safe tick
    w.settings['monitor_check_interval'] = 999
    try:
        w.monitor_autostart.setChecked(True)             # fires the toggle
        assert w.settings['monitor_autostart'] is True
        assert saved.get('monitor_autostart') is True    # persisted
        assert w._monitor_running() is True
    finally:
        w.monitor_autostart.setChecked(False)
    assert w._monitor_running() is False
