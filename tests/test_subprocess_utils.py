"""utils/subprocess_utils.py — hidden-window child processes (offline).

On Windows the helpers must inject CREATE_NO_WINDOW (+ a hidden STARTUPINFO) so
external CLIs (amass/nuclei/katana/subfinder/bbot/yt-dlp/ffmpeg/scrapy…) never
flash a console window under the GUI; on POSIX they are pass-throughs. Tests are
platform-aware so the suite passes on both.
"""
import subprocess
import sys

from utils import subprocess_utils as su

_WIN = sys.platform == 'win32'


# ── hidden_kwargs ───────────────────────────────────────────────────────────────

def test_hidden_kwargs_sets_no_window_on_windows():
    kw = su.hidden_kwargs()
    if _WIN:
        assert kw['creationflags'] & subprocess.CREATE_NO_WINDOW
        si = kw['startupinfo']
        assert si.dwFlags & subprocess.STARTF_USESHOWWINDOW
        assert si.wShowWindow == subprocess.SW_HIDE
    else:
        assert kw == {}                       # no-op off Windows


def test_hidden_kwargs_merges_extra_and_ors_creationflags():
    kw = su.hidden_kwargs(cwd='.', creationflags=0x00000008)  # DETACHED_PROCESS bit
    assert kw['cwd'] == '.'
    if _WIN:
        assert kw['creationflags'] & subprocess.CREATE_NO_WINDOW
        assert kw['creationflags'] & 0x00000008   # caller's flag preserved (OR-ed)
    else:
        assert 'creationflags' in kw and kw['creationflags'] == 0x00000008


def test_run_hidden_passes_flags(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured['args'] = args
        captured['kwargs'] = kwargs
        return 'ok'

    monkeypatch.setattr(su.subprocess, 'run', fake_run)
    out = su.run_hidden(['whoami'], capture_output=True)
    assert out == 'ok'
    assert captured['args'] == (['whoami'],)
    assert captured['kwargs'].get('capture_output') is True
    if _WIN:
        assert captured['kwargs']['creationflags'] & subprocess.CREATE_NO_WINDOW


def test_popen_hidden_passes_flags(monkeypatch):
    captured = {}

    def fake_popen(*args, **kwargs):
        captured['kwargs'] = kwargs
        return 'proc'

    monkeypatch.setattr(su.subprocess, 'Popen', fake_popen)
    assert su.popen_hidden(['x']) == 'proc'
    if _WIN:
        assert captured['kwargs']['creationflags'] & subprocess.CREATE_NO_WINDOW


# ── integration: external_tools.run_command routes through the helper ──────────

def test_run_command_hides_window(monkeypatch):
    from core import external_tools

    captured = {}

    class _Proc:
        returncode, stdout, stderr = 0, 'out', ''

    def fake_run(*args, **kwargs):
        captured['kwargs'] = kwargs
        return _Proc()

    monkeypatch.setattr(su.subprocess, 'run', fake_run)
    res = external_tools.run_command(['nuclei', '-version'], timeout=5)
    assert res['rc'] == 0 and res['stdout'] == 'out'
    if _WIN:
        assert captured['kwargs']['creationflags'] & subprocess.CREATE_NO_WINDOW
