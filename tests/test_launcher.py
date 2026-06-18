"""Launcher & dependency-management engine (core/launcher.py, EPIC 6).

Pure / offline: the subprocess seam (``run``) and the launch ``spawn`` are injected,
so health/repair/update/install/launch are exercised without installing anything or
starting a process. Reuses core.features (optional layer) and PathManager.
"""

from core import launcher


def _ok(cmd, rc=0, **extra):
    return {'rc': rc, 'stdout': '', 'stderr': '', **extra}


# ── health ─────────────────────────────────────────────────────────────────────

def test_health_check_all_required_present():
    h = launcher.health_check(has_module=lambda m: True,
                              check_writable=lambda: True)
    assert h['ok'] is True and h['required_ok'] is True
    assert all(r['ok'] for r in h['required'])
    assert {r['name'] for r in h['required']} == set(launcher.REQUIRED)
    assert 'playwright' in h['optional']      # reuses features.summary()
    assert h['data_root_writable'] is True
    assert h['python_version'].count('.') == 2


def test_health_check_flags_missing_required():
    h = launcher.health_check(has_module=lambda m: m != 'requests',
                              check_writable=lambda: True)
    assert h['ok'] is False and h['required_ok'] is False
    bad = next(r for r in h['required'] if r['name'] == 'requests')
    assert bad['ok'] is False


def test_health_check_flags_unwritable_data_root():
    h = launcher.health_check(has_module=lambda m: True,
                              check_writable=lambda: False)
    assert h['data_root_writable'] is False
    assert h['ok'] is True       # required deps fine; writability is separate


def test_data_root_writable_real_check():
    # The real probe writes/removes a file under the PathManager data root.
    assert launcher._data_root_writable() is True


# ── install optional ────────────────────────────────────────────────────────────

def test_install_optional_pip_success():
    calls = []
    res = launcher.install_optional(
        'scrapy', run=lambda cmd, **k: calls.append(cmd) or _ok(cmd))
    assert res['status'] == 'ok' and res['method'] == 'pip'
    assert calls and 'scrapy' in calls[0] and 'install' in calls[0]


def test_install_optional_pip_failure_surfaces_stderr():
    res = launcher.install_optional(
        'fastapi', run=lambda cmd, **k: _ok(cmd, rc=1, stderr='boom'))
    assert res['status'] == 'failed' and res['error'] == 'boom'


def test_install_playwright_adds_browser_note():
    res = launcher.install_optional('playwright', run=lambda cmd, **k: _ok(cmd))
    assert res['status'] == 'ok' and 'chromium' in res['note']


def test_install_optional_binary_is_manual_with_url():
    ran = []
    res = launcher.install_optional('nuclei', run=lambda cmd, **k: ran.append(cmd))
    assert res['status'] == 'manual' and res['method'] == 'manual'
    assert 'github.com/projectdiscovery/nuclei' in res['url']
    assert ran == []           # never shells out for a binary


def test_install_optional_unknown():
    res = launcher.install_optional('bogus', run=lambda cmd, **k: _ok(cmd))
    assert res['status'] == 'unknown' and 'bogus' in res['error']


def test_installable_components_split_pip_vs_manual():
    comp = launcher.installable_components()
    assert comp['scrapy']['method'] == 'pip'
    assert comp['nuclei']['method'] == 'manual' and 'url' in comp['nuclei']


# ── repair / update ──────────────────────────────────────────────────────────────

def test_repair_runs_requirements_install():
    calls = []
    res = launcher.repair(run=lambda cmd, **k: calls.append(cmd) or _ok(cmd))
    assert res['status'] == 'ok'
    assert '-r' in calls[0] and any('requirements.txt' in str(p) for p in calls[0])


def test_update_pip_upgrade_and_optional_git():
    calls = []
    res = launcher.update(run=lambda cmd, **k: calls.append(cmd) or _ok(cmd),
                          git=False)
    assert res['status'] == 'ok'
    assert any('--upgrade' in c for c in calls)
    assert all(s['step'] != 'git-pull' for s in res['steps'])   # git disabled


def test_update_reports_failed_step():
    res = launcher.update(
        run=lambda cmd, **k: _ok(cmd, rc=1, stderr='x'), git=False)
    assert res['status'] == 'failed'


# ── launch ───────────────────────────────────────────────────────────────────────

def test_launch_app_invokes_spawn():
    spawned = []
    res = launcher.launch_app(spawn=lambda: spawned.append(True))
    assert res['status'] == 'ok' and spawned == [True]


def test_launch_app_reports_failure():
    def boom():
        raise OSError('no exe')
    res = launcher.launch_app(spawn=boom)
    assert res['status'] == 'failed' and 'no exe' in res['error']
