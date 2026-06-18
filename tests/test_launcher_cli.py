"""Launcher front-end (launcher.py, EPIC 6 Module 5) — CLI dispatch + Qt window.

The engine is stubbed so dispatch/exit-codes are checked without installing
anything; the window build is headless (qapp).
"""

import launcher


# ── CLI dispatch (exit codes + the engine call it routes to) ─────────────────

def test_cli_health_ok(monkeypatch, capsys):
    monkeypatch.setattr(launcher.engine, 'health_check', lambda: {
        'python_version': '3.11.0', 'data_root_writable': True, 'ok': True,
        'required': [{'name': 'qtpy', 'ok': True}],
        'optional': {'nuclei': {'available': False, 'enables': 'x'}}})
    rc = launcher.run_cli(['--health'])
    out = capsys.readouterr().out
    assert rc == 0 and 'HEALTHY' in out and 'qtpy' in out


def test_cli_health_problems_exit_1(monkeypatch):
    monkeypatch.setattr(launcher.engine, 'health_check', lambda: {
        'python_version': '3.11.0', 'data_root_writable': True, 'ok': False,
        'required': [{'name': 'requests', 'ok': False}], 'optional': {}})
    assert launcher.run_cli(['--health']) == 1


def test_cli_components(monkeypatch, capsys):
    monkeypatch.setattr(launcher.engine, 'installable_components', lambda: {
        'scrapy': {'method': 'pip', 'packages': ['scrapy'], 'enables': 'crawl'},
        'nuclei': {'method': 'manual', 'url': 'http://x', 'enables': 'vulns'}})
    assert launcher.run_cli(['--components']) == 0
    out = capsys.readouterr().out
    assert 'pip install scrapy' in out and 'manual — http://x' in out


def test_cli_install_manual_exit_0(monkeypatch):
    monkeypatch.setattr(launcher.engine, 'install_optional',
                        lambda name: {'status': 'manual', 'note': 'get it'})
    assert launcher.run_cli(['--install', 'nuclei']) == 0


def test_cli_install_failure_exit_1(monkeypatch):
    monkeypatch.setattr(launcher.engine, 'install_optional',
                        lambda name: {'status': 'failed', 'error': 'boom'})
    assert launcher.run_cli(['--install', 'scrapy']) == 1


def test_cli_repair_and_update(monkeypatch, capsys):
    monkeypatch.setattr(launcher.engine, 'repair', lambda: {'status': 'ok'})
    monkeypatch.setattr(launcher.engine, 'update', lambda: {
        'status': 'ok', 'steps': [{'step': 'pip-upgrade', 'ok': True}]})
    assert launcher.run_cli(['--repair']) == 0
    assert launcher.run_cli(['--update']) == 0
    assert 'Update: ok' in capsys.readouterr().out


def test_cli_launch(monkeypatch):
    monkeypatch.setattr(launcher.engine, 'launch_app', lambda: {'status': 'ok'})
    assert launcher.run_cli(['--launch']) == 0


# ── Qt window (Module 5) — builds headless with the five actions ─────────────

def test_launcher_window_builds_with_five_actions(qapp, monkeypatch):
    # Stub the engine so building the window does no real I/O.
    monkeypatch.setattr(launcher.engine, 'health_check', lambda: {
        'python_version': '3.11.0', 'data_root_writable': True, 'ok': True,
        'required': [{'name': 'qtpy', 'ok': True}], 'optional': {}})
    win = launcher._build_window()
    assert set(win.buttons) == {'launch', 'health', 'repair', 'components', 'install'}
    monkeypatch.setattr(launcher.engine, 'installable_components',
                        lambda: {'scrapy': {'method': 'pip', 'packages': ['scrapy'],
                                            'enables': 'crawl'}})
    win.on_components()          # synchronous action runs without error
