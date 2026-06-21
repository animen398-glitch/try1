"""core/launcher.py
Launcher & dependency-management engine (EPIC 6) — pure, offline-first.

One place that answers the launcher's questions — *is the install healthy, can it
be repaired/updated, what optional tools are present, how do I install one, how do I
start the app* — without a mandatory update server and without re-implementing what
already exists. It **reuses** the dependency checks (``core.features`` for the
optional layer), the path authority (``core.paths.PathManager``), and the
never-raising subprocess wrapper (``core.external_tools.run_command``). The thin
``launcher.py`` UI/CLI is just a front-end over these functions.

Testable / offline: every action that shells out (pip, launching the app)
takes an injectable seam (``run`` / ``spawn``), so tests drive the whole flow
without installing anything or starting a process.
"""

import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

from core.features import OPTIONAL_FEATURES, _has_module
from core.features import summary as optional_summary

# Hard requirements — the app cannot import/start without these (display name →
# import module). lxml is intentionally NOT here: it is optional (bs4 falls back to
# the stdlib parser), and core.features already lists it under the optional layer.
REQUIRED = {
    'qtpy': 'qtpy',
    'PySide6': 'PySide6',
    'requests': 'requests',
    'beautifulsoup4': 'bs4',
}

# Optional features installable from PyPI → the pip arguments that install them.
_PIP_INSTALL: Dict[str, List[str]] = {
    'playwright': ['playwright'],
    'yt-dlp': ['yt-dlp'],
    'fastapi': ['fastapi', 'uvicorn[standard]'],
    'lxml': ['lxml'],
    'scrapy': ['scrapy'],
}

# External binaries — cannot be pip-installed (Go binaries / system tools); the
# launcher shows where to get them and to put them on PATH (per the EPIC decision).
_BINARY_HELP: Dict[str, str] = {
    'ffmpeg': 'https://ffmpeg.org/download.html',
    'nuclei': 'https://github.com/projectdiscovery/nuclei',
    'katana': 'https://github.com/projectdiscovery/katana',
    'amass': 'https://github.com/owasp-amass/amass',
    'subfinder': 'https://github.com/projectdiscovery/subfinder',
    'httpx': 'https://github.com/projectdiscovery/httpx',
}

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_REQUIREMENTS = _PROJECT_ROOT / 'requirements.txt'


# ── subprocess seam (never raises; reused from external_tools) ────────────────

def _run(cmd: List[str], timeout: int = 600) -> Dict:
    """Run a command and return ``{rc, stdout, stderr, ...}`` — never raises
    (delegates to the shared ``external_tools.run_command``)."""
    from core.external_tools import run_command
    return run_command(cmd, timeout)


def _pip(*args: str) -> List[str]:
    """``pip`` invocation for the *current* interpreter (works in a venv)."""
    return [sys.executable, '-m', 'pip', *args]


# ── health (Check Health / View Installed Components) ─────────────────────────

def _data_root_writable() -> bool:
    """Whether the writable data root accepts a file (PathManager is the authority
    — never duplicated). A real, offline, local check."""
    try:
        from core.paths import get_path_manager
        probe = get_path_manager().get_temp_path() / '.launcher_write_test'
        probe.write_text('ok', encoding='utf-8')
        probe.unlink()
        return True
    except Exception:   # noqa: BLE001 — an unwritable data root is a health *result*
        return False


def health_check(*, has_module: Optional[Callable] = None,
                 check_writable: Optional[Callable] = None) -> Dict:
    """Full health snapshot for the launcher (pure given the injected probes).

    ``required`` lists each hard dependency and whether it imports; ``optional`` is
    the existing ``features.summary()`` (reused, not re-derived); plus the Python
    version and whether the data root is writable. ``ok`` is true only when every
    required dependency is present."""
    has_module = has_module or _has_module
    check_writable = check_writable or _data_root_writable
    required = [{'name': n, 'module': m, 'ok': bool(has_module(m))}
                for n, m in REQUIRED.items()]
    return {
        'python_version': '.'.join(map(str, sys.version_info[:3])),
        'required': required,
        'required_ok': all(r['ok'] for r in required),
        'optional': optional_summary(),
        'data_root_writable': bool(check_writable()),
        'ok': all(r['ok'] for r in required),
    }


def installable_components() -> Dict[str, Dict]:
    """Every optional component the launcher can act on → ``{method, target/url,
    enables}``. ``method`` is ``pip`` (installable here) or ``manual`` (external
    binary, instructions only). Drives the 'Install Optional Tools' list."""
    out: Dict[str, Dict] = {}
    for name, (enables, _detect) in OPTIONAL_FEATURES.items():
        if name in _PIP_INSTALL:
            out[name] = {'method': 'pip', 'packages': _PIP_INSTALL[name],
                         'enables': enables}
        elif name in _BINARY_HELP:
            out[name] = {'method': 'manual', 'url': _BINARY_HELP[name],
                         'enables': enables}
    return out


# ── install / repair / update (offline-first; no mandatory update server) ─────

def install_optional(name: str, *, run: Optional[Callable] = None) -> Dict:
    """Install one optional component.

    A PyPI feature is pip-installed; an external binary returns manual
    instructions + its homepage (it cannot be pip-installed). Unknown names report
    an error. The subprocess seam ``run`` is injected in tests."""
    run = run or _run
    if name in _PIP_INSTALL:
        pkgs = _PIP_INSTALL[name]
        res = run(_pip('install', *pkgs))
        ok = res.get('rc') == 0
        out = {'name': name, 'method': 'pip', 'packages': pkgs,
               'status': 'ok' if ok else 'failed', 'rc': res.get('rc'),
               'error': res.get('error') or (None if ok else res.get('stderr'))}
        if name == 'playwright' and ok:
            out['note'] = ('Run "python -m playwright install chromium" to fetch '
                           'the browser.')
        return out
    if name in _BINARY_HELP:
        url = _BINARY_HELP[name]
        return {'name': name, 'method': 'manual', 'status': 'manual', 'url': url,
                'note': (f'{name} is an external binary — install it from {url} '
                         f'and put it on your PATH.')}
    return {'name': name, 'status': 'unknown',
            'error': f'unknown component: {name}'}


def repair(*, run: Optional[Callable] = None) -> Dict:
    """Reinstall the required dependencies (``pip install -r requirements.txt``)."""
    run = run or _run
    res = run(_pip('install', '-r', str(_REQUIREMENTS)))
    ok = res.get('rc') == 0
    return {'action': 'repair', 'status': 'ok' if ok else 'failed',
            'rc': res.get('rc'),
            'error': res.get('error') or (None if ok else res.get('stderr'))}


def update(*, run: Optional[Callable] = None, git: bool = False) -> Dict:
    """Update in place — offline-first, no mandatory update server.

    Upgrades the pinned dependencies (``pip install --upgrade -r requirements.txt``).
    Remote git operations are intentionally not performed here: project policy
    forbids ``git pull``/``fetch``/``push``/``clone`` without explicit one-off
    human approval. The ``git`` argument is accepted for backward compatibility
    with older callers/tests, but ignored."""
    run = run or _run
    steps: List[Dict] = []
    pip_res = run(_pip('install', '--upgrade', '-r', str(_REQUIREMENTS)))
    steps.append({'step': 'pip-upgrade', 'rc': pip_res.get('rc'),
                  'ok': pip_res.get('rc') == 0})
    ok = all(s['ok'] for s in steps)
    return {'action': 'update', 'status': 'ok' if ok else 'failed', 'steps': steps}


# ── launch ────────────────────────────────────────────────────────────────────

def _spawn_app() -> None:
    """Start the main application as a detached child process (source mode runs
    ``python main.py``; a frozen build re-launches its own bundle)."""
    import subprocess
    if getattr(sys, 'frozen', False):
        subprocess.Popen([sys.executable, '--app'])      # frozen: app mode flag
    else:
        subprocess.Popen([sys.executable, str(_PROJECT_ROOT / 'main.py')])


def launch_app(*, spawn: Optional[Callable] = None) -> Dict:
    """Launch the main application (detached). ``spawn`` is injected in tests so no
    process is actually started."""
    spawn = spawn or _spawn_app
    try:
        spawn()
        return {'action': 'launch', 'status': 'ok'}
    except Exception as e:   # noqa: BLE001 — a failed launch is a reported result
        return {'action': 'launch', 'status': 'failed', 'error': str(e)}
