"""Security Audit tab — Stop button + progress wiring (headless, no network)."""

import threading


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def test_stop_button_present_and_initially_disabled(qapp):
    w = _window(qapp)
    assert hasattr(w, 'btn_security_stop')
    assert not w.btn_security_stop.isEnabled()       # nothing running yet


def test_stop_sets_cancel_event_and_disables_button(qapp):
    w = _window(qapp)
    w._security_cancel = threading.Event()
    w.btn_security_stop.setEnabled(True)
    w._stop_security_audit()
    assert w._security_cancel.is_set()               # cooperative cancel signalled
    assert not w.btn_security_stop.isEnabled()


def test_progress_updates_status_and_strips_prefix(qapp):
    w = _window(qapp)
    w._on_security_progress('[SecurityAudit] Fetching page: https://x')
    assert w.security_status.text() == 'Fetching page: https://x'


def test_reset_buttons_toggles_run_and_stop(qapp):
    w = _window(qapp)
    w.btn_security_scan.setEnabled(False)
    w.btn_security_stop.setEnabled(True)
    w._reset_security_buttons()
    assert w.btn_security_scan.isEnabled()
    assert not w.btn_security_stop.isEnabled()


def test_done_shows_cancelled_prefix_with_partial_results(qapp):
    w = _window(qapp)
    w._security_cancel = threading.Event()
    w._security_cancel.set()                          # audit was stopped
    w._on_security_done({
        'status': 'Success',
        'secrets': [], 'source_maps': [],
        'summary': {'secrets': 0, 'secrets_valid_format': 0,
                    'endpoints': 2, 'source_maps': 0, 'maps_with_content': 0,
                    'scanned_scripts': 1},
    })
    assert 'Остановлено' in w.security_status.text()
    assert 'эндпоинтов: 2' in w.security_status.text()
    # Buttons returned to the idle state.
    assert w.btn_security_scan.isEnabled()
    assert not w.btn_security_stop.isEnabled()
