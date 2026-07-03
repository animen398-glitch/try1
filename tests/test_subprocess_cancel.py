"""tests/test_subprocess_cancel.py

The cancellable hidden-process contract in ``utils.subprocess_utils``: hidden
flags on the Popen path, timeout, cooperative cancellation, process-tree
cleanup, missing binary, non-zero exit and output truncation. All offline — the
only child spawned is a local ``python -c`` snippet (no network, no real scan).
"""

import subprocess
import sys
import threading
import time

import pytest

from utils import subprocess_utils as su
from utils.subprocess_utils import CancellationToken, run_capture

_WIN = sys.platform == 'win32'
_PY = sys.executable


def _py(code):
    return [_PY, '-c', code]


# ── CancellationToken ─────────────────────────────────────────────────────────

def test_cancellation_token_flag():
    tok = CancellationToken()
    assert tok.is_set() is False and tok.cancelled is False
    tok.cancel()
    assert tok.is_set() is True and tok.cancelled is True


# ── hidden flags on the Popen path ────────────────────────────────────────────

def test_run_capture_uses_hidden_popen(monkeypatch):
    captured = {}

    class _FakeProc:
        returncode = 0

        def __init__(self):
            import io
            self.stdout = io.StringIO('')
            self.stderr = io.StringIO('')
            self.stdin = None

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def fake_popen(*a, **kw):
        captured['kwargs'] = kw
        return _FakeProc()

    monkeypatch.setattr(su.subprocess, 'Popen', fake_popen)
    res = run_capture(['x'], timeout=5)
    assert res['rc'] == 0 and res['cancelled'] is False
    if _WIN:
        assert captured['kwargs']['creationflags'] & subprocess.CREATE_NO_WINDOW


# ── integration: real child process ───────────────────────────────────────────

def test_run_capture_normal_run():
    res = run_capture(_py('import sys; print("hi"); sys.stderr.write("warn")'),
                      timeout=15)
    assert res['rc'] == 0
    assert res['stdout'].strip() == 'hi'
    assert 'warn' in res['stderr']
    assert res['timed_out'] is False and res['cancelled'] is False


def test_run_capture_nonzero_exit():
    res = run_capture(_py('import sys; sys.exit(3)'), timeout=15)
    assert res['rc'] == 3
    assert res['timed_out'] is False and res['cancelled'] is False


def test_run_capture_timeout_kills_process():
    res = run_capture(_py('import time; time.sleep(30)'), timeout=1)
    assert res['timed_out'] is True
    assert res['cancelled'] is False
    assert res['rc'] is None


def test_run_capture_cancellation_is_prompt():
    tok = CancellationToken()

    def _cancel_soon():
        time.sleep(0.5)
        tok.cancel()

    threading.Thread(target=_cancel_soon, daemon=True).start()
    t0 = time.monotonic()
    res = run_capture(_py('import time; time.sleep(30)'), timeout=60,
                      cancel_event=tok)
    elapsed = time.monotonic() - t0
    assert res['cancelled'] is True
    assert res['timed_out'] is False
    assert elapsed < 10          # killed promptly, not after the 60s timeout


def test_run_capture_missing_binary():
    res = run_capture(['definitely_no_such_binary_zzz'], timeout=5)
    assert res.get('error')
    assert res['stdout'] == '' and res['cancelled'] is False


def test_run_capture_stdin_and_truncation():
    res = run_capture(_py('import sys; sys.stdout.write(sys.stdin.read())'),
                      timeout=15, input_text='abcdefghij', max_output=4)
    assert res['stdout'] == 'abcd'
    assert res['truncated'] is True


# ── terminate_process_tree ────────────────────────────────────────────────────

def test_terminate_process_tree_kills_running_child():
    proc = su.popen_hidden(_py('import time; time.sleep(30)'),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           **({'start_new_session': True} if not _WIN else {}))
    assert proc.poll() is None            # running
    su.terminate_process_tree(proc)
    # Give the OS a moment to reap.
    for _ in range(50):
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    assert proc.poll() is not None        # dead


def test_terminate_process_tree_safe_on_dead_and_none():
    su.terminate_process_tree(None)       # no raise
    proc = su.popen_hidden(_py('pass'), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    proc.wait(timeout=10)
    su.terminate_process_tree(proc)       # already exited → no raise


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
