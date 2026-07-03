"""utils/subprocess_utils.py
Single seam for spawning child processes WITHOUT a flashing console window.

On Windows every ``subprocess.run``/``Popen`` for a console program (amass,
nuclei, katana, subfinder, bbot, rar, the Scrapy child, …) pops
a transient ``cmd``/``conhost`` window when the parent is a GUI app. Passing
``CREATE_NO_WINDOW`` + a hidden ``STARTUPINFO`` suppresses it. On POSIX these
flags don't exist and the helpers are plain pass-throughs.

Use ``run_hidden`` / ``popen_hidden`` exactly like ``subprocess.run`` /
``subprocess.Popen`` — they only inject the no-window flags (caller kwargs win,
so an explicit ``creationflags`` is preserved/OR-ed by the caller if needed).
stdout/stderr capture and every other argument behave unchanged.

For long-running external tools that must be **cancellable** (a GUI "Cancel"
button) and reliably killed with their whole child tree, use ``run_capture`` —
a hidden ``Popen`` with a poll loop honouring a timeout and a cancellation
token, returning a structured, never-raising result. ``terminate_process_tree``
does the OS-correct tree kill (``taskkill /T`` on Windows, process-group kill on
POSIX). This is the ONE module permitted to import ``subprocess`` directly (the
``test_no_direct_subprocess`` architectural guard enforces it).
"""
import subprocess
import sys
import threading
import time

_IS_WINDOWS = sys.platform == 'win32'

# CREATE_NO_WINDOW exists only on Windows; 0 elsewhere makes the OR a no-op.
CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

# Default cap on captured stdout so a runaway/misbehaving tool can't exhaust
# memory through us (mirrors external_tools.MAX_OUTPUT).
MAX_CAPTURE = 8_000_000  # characters (~8 MB of text)


def _startupinfo():
    """A hidden STARTUPINFO on Windows (belt-and-braces with CREATE_NO_WINDOW),
    else None."""
    if not _IS_WINDOWS:
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return si


def hidden_kwargs(**extra) -> dict:
    """Subprocess kwargs that hide the console window on Windows (no-op on POSIX).

    ``extra`` is merged on top, so callers may add/override fields. A caller-
    supplied ``creationflags`` is OR-ed with CREATE_NO_WINDOW; an explicit
    ``startupinfo`` wins outright.
    """
    if not _IS_WINDOWS:
        return dict(extra)
    kw = {'creationflags': CREATE_NO_WINDOW, 'startupinfo': _startupinfo()}
    if 'creationflags' in extra:
        kw['creationflags'] = int(extra.pop('creationflags')) | CREATE_NO_WINDOW
    kw.update(extra)
    return kw


def run_hidden(*args, **kwargs):
    """``subprocess.run`` with the console window hidden on Windows."""
    return subprocess.run(*args, **hidden_kwargs(**kwargs))


def popen_hidden(*args, **kwargs):
    """``subprocess.Popen`` with the console window hidden on Windows."""
    return subprocess.Popen(*args, **hidden_kwargs(**kwargs))


# ── cancellation token ────────────────────────────────────────────────────────

class CancellationToken:
    """A tiny thread-safe cancel flag, compatible with ``run_capture``.

    Thin wrapper over ``threading.Event`` so a GUI worker can hand the same
    token to a background tool run and later call ``cancel()`` from any thread.
    ``run_capture`` accepts this token or any object exposing ``is_set()`` (a
    bare ``threading.Event`` works too), so it plugs into the existing
    TaskRunnerMixin worker model without new threading plumbing.
    """

    __slots__ = ('_event',)

    def __init__(self):
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


# ── process-tree termination ──────────────────────────────────────────────────

def terminate_process_tree(proc, *, timeout: int = 5) -> None:
    """Best-effort kill of ``proc`` and all its descendants (never raises).

    A recon/audit CLI often spawns its own children; killing only the immediate
    child leaves orphans running. On Windows ``taskkill /T /F`` walks the whole
    tree by PID (run hidden, so cancelling never flashes a console); on POSIX we
    kill the process group created with ``start_new_session`` in ``run_capture``.
    Falls back to ``proc.kill()``. Safe to call on an already-exited process.
    """
    if proc is None:
        return
    try:
        if proc.poll() is not None:
            return
    except Exception:
        return
    if _IS_WINDOWS:
        try:
            subprocess.run(
                ['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                **hidden_kwargs(stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout))
            return
        except Exception:
            pass
    else:
        try:
            import os
            import signal
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except Exception:
            pass
    try:
        proc.kill()
    except Exception:
        pass


def _drain(stream, chunks: list) -> None:
    """Read a text pipe to EOF into ``chunks`` (runs in a daemon thread)."""
    try:
        for line in iter(stream.readline, ''):
            chunks.append(line)
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _cap(text: str, limit: int) -> tuple:
    """Return ``(text_capped_to_limit, was_truncated)`` keeping the head."""
    text = text or ''
    if len(text) > limit:
        return text[:limit], True
    return text, False


def run_capture(cmd, *, timeout=None, input_text=None, cancel_event=None,
                max_output: int = MAX_CAPTURE, poll_interval: float = 0.1,
                cwd=None, env=None) -> dict:
    """Run ``cmd`` hidden and cancellably; return a structured, never-raising result.

    ``{rc, stdout, stderr, timed_out, cancelled, truncated, error?}`` — the same
    shape ``external_tools.run_command`` promises, so it is a drop-in for the
    cancellable path. Output is drained on reader threads (no pipe-buffer
    deadlock) and capped to ``max_output`` chars (``truncated`` flags a cap).
    A missing binary / OS error is reported via ``error``; a ``timeout`` sets
    ``timed_out``; a set ``cancel_event`` sets ``cancelled`` — both kill the whole
    process tree. ``rc`` is the child's exit code only on a clean finish.
    """
    result = {'rc': None, 'stdout': '', 'stderr': '', 'timed_out': False,
              'cancelled': False, 'truncated': False}

    extra = {}
    if not _IS_WINDOWS:
        # Own session/group so terminate_process_tree can kill descendants.
        extra['start_new_session'] = True
    try:
        proc = popen_hidden(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=(subprocess.PIPE if input_text is not None else None),
            text=True, bufsize=1, cwd=cwd, env=env, **extra)
    except FileNotFoundError:
        result['error'] = 'binary not found on PATH'
        return result
    except OSError as e:  # noqa: BLE001 — surface, don't crash
        result['error'] = str(e)
        return result

    out_chunks: list = []
    err_chunks: list = []
    t_out = threading.Thread(target=_drain, args=(proc.stdout, out_chunks),
                             daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, err_chunks),
                             daemon=True)
    t_out.start()
    t_err.start()

    if input_text is not None:
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except Exception:
            pass

    deadline = (time.monotonic() + timeout) if timeout else None
    while True:
        try:
            proc.wait(timeout=poll_interval)
            break
        except subprocess.TimeoutExpired:
            pass
        if cancel_event is not None and cancel_event.is_set():
            result['cancelled'] = True
            terminate_process_tree(proc)
            break
        if deadline is not None and time.monotonic() >= deadline:
            result['timed_out'] = True
            terminate_process_tree(proc)
            break

    # Let the kill land and the reader threads drain the closed pipes.
    try:
        proc.wait(timeout=5)
    except Exception:
        pass
    t_out.join(timeout=5)
    t_err.join(timeout=5)

    stdout, truncated = _cap(''.join(out_chunks), max_output)
    result['stdout'] = stdout
    result['stderr'] = (''.join(err_chunks))[-1000:]
    result['truncated'] = truncated
    if not (result['cancelled'] or result['timed_out']):
        result['rc'] = proc.returncode
    return result
