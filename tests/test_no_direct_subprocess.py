"""tests/test_no_direct_subprocess.py

Architectural guard: the ONLY place allowed to touch ``subprocess.run`` /
``subprocess.Popen`` / ``os.system`` / ``shell=True`` is the single process seam
``utils/subprocess_utils.py``. Every other production module must go through
``run_hidden`` / ``popen_hidden`` / ``core.external_tools.run_command`` so that on
Windows a child process never flashes a console window (CREATE_NO_WINDOW + hidden
STARTUPINFO) and so timeout/cancel/redaction are centralised.

This is an *AST* check, not a brittle text grep: it parses each production file
and inspects the call graph, so it ignores mentions in strings/comments/docstrings
and correctly follows ``from subprocess import Popen`` style aliases.

Scope: our own production packages + the repo-root entry scripts. Tests,
vendored third-party sources (``vendor/``, ``tools/``) and build artefacts are
deliberately not scanned — they are gitignored and not shipped as our code.
"""

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# The one seam that is permitted to call subprocess directly.
_ALLOWED = {_REPO_ROOT / 'utils' / 'subprocess_utils.py'}

# Our production packages (recursed) + every repo-root-level entry script.
_PRODUCTION_PACKAGES = ('core', 'gui', 'utils', 'remote', 'plugins')

# subprocess members that spawn/await a child process (attribute or from-import).
_FORBIDDEN_SUBPROCESS = {'run', 'Popen', 'call', 'check_call', 'check_output'}


def _production_files():
    """Yield every production ``*.py`` to scan (excluding the allowed seam)."""
    seen = set()
    for pkg in _PRODUCTION_PACKAGES:
        base = _REPO_ROOT / pkg
        if not base.is_dir():
            continue
        for path in base.rglob('*.py'):
            if '__pycache__' in path.parts:
                continue
            seen.add(path.resolve())
    # Repo-root entry scripts (main.py, *_cli.py, launcher.py, …) — top level only.
    for path in _REPO_ROOT.glob('*.py'):
        seen.add(path.resolve())
    return sorted(p for p in seen if p not in _ALLOWED)


class _ProcessCallVisitor(ast.NodeVisitor):
    """Collect forbidden process-spawn call sites in one module."""

    def __init__(self):
        # name bound to the ``subprocess`` module (``import subprocess as sp``)
        self._subprocess_aliases = {'subprocess'}
        # name bound to ``os`` module
        self._os_aliases = {'os'}
        # names bound to forbidden callables via ``from subprocess import run``
        self._forbidden_names = {}   # bound_name -> original ("run"/"Popen"/…)
        # ``from os import system`` bound names
        self._os_system_names = set()
        self.violations = []          # list[(lineno, description)]

    # ── track imports so aliases are handled ────────────────────────────────
    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == 'subprocess':
                self._subprocess_aliases.add(alias.asname or 'subprocess')
            elif alias.name == 'os':
                self._os_aliases.add(alias.asname or 'os')
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == 'subprocess':
            for alias in node.names:
                if alias.name in _FORBIDDEN_SUBPROCESS:
                    self._forbidden_names[alias.asname or alias.name] = alias.name
        elif node.module == 'os':
            for alias in node.names:
                if alias.name == 'system':
                    self._os_system_names.add(alias.asname or 'system')
        self.generic_visit(node)

    # ── inspect every call ──────────────────────────────────────────────────
    def visit_Call(self, node):
        self._check_shell_true(node)
        func = node.func
        if isinstance(func, ast.Attribute):
            val = func.value
            if isinstance(val, ast.Name):
                if (val.id in self._subprocess_aliases
                        and func.attr in _FORBIDDEN_SUBPROCESS):
                    self.violations.append(
                        (node.lineno, f'subprocess.{func.attr}(...)'))
                elif val.id in self._os_aliases and func.attr == 'system':
                    self.violations.append((node.lineno, 'os.system(...)'))
        elif isinstance(func, ast.Name):
            if func.id in self._forbidden_names:
                self.violations.append(
                    (node.lineno,
                     f'subprocess.{self._forbidden_names[func.id]}(...) '
                     '(via from-import)'))
            elif func.id in self._os_system_names:
                self.violations.append((node.lineno, 'os.system(...) (via from-import)'))
        self.generic_visit(node)

    def _check_shell_true(self, node):
        for kw in node.keywords:
            if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) \
                    and kw.value.value is True:
                self.violations.append((node.lineno, 'shell=True'))


def _scan(path: Path):
    source = path.read_text(encoding='utf-8', errors='ignore')
    tree = ast.parse(source, filename=str(path))
    visitor = _ProcessCallVisitor()
    visitor.visit(tree)
    return visitor.violations


def test_no_direct_process_spawn_outside_seam():
    """No production file (other than the seam) spawns a process directly."""
    offenders = []
    for path in _production_files():
        for lineno, what in _scan(path):
            rel = path.relative_to(_REPO_ROOT)
            offenders.append(f'{rel.as_posix()}:{lineno}: {what}')
    assert not offenders, (
        'Direct process spawning is only allowed in utils/subprocess_utils.py. '
        'Route through run_hidden / popen_hidden / external_tools.run_command. '
        'Offenders:\n  ' + '\n  '.join(offenders))


def test_seam_is_scannable_and_excluded():
    """Sanity: the seam file exists, is excluded, and itself would be flagged
    (proving the detector actually detects — no false-green)."""
    seam = _REPO_ROOT / 'utils' / 'subprocess_utils.py'
    assert seam.exists()
    assert seam.resolve() not in set(_production_files())
    # The detector must find the direct subprocess.run/Popen inside the seam.
    assert _scan(seam), 'detector failed to flag the seam — it is not working'


def test_detector_flags_shell_true(tmp_path):
    sample = tmp_path / 'sample.py'
    sample.write_text('import subprocess\n'
                      'subprocess.run(["x"], shell=True)\n', encoding='utf-8')
    found = {what for _, what in _scan(sample)}
    assert 'shell=True' in found
    assert 'subprocess.run(...)' in found


def test_detector_follows_from_import(tmp_path):
    sample = tmp_path / 'sample.py'
    sample.write_text('from subprocess import Popen as P\n'
                      'P(["x"])\n', encoding='utf-8')
    found = {what for _, what in _scan(sample)}
    assert any('Popen' in w for w in found)


def test_production_scan_is_non_empty():
    """Guard against a mis-configured scan silently passing (0 files scanned)."""
    files = _production_files()
    assert len(files) > 50
    names = {p.name for p in files}
    assert 'external_tools.py' in names
    assert 'subprocess_utils.py' not in names   # the seam is excluded
