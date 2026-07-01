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
"""
import subprocess
import sys

_IS_WINDOWS = sys.platform == 'win32'

# CREATE_NO_WINDOW exists only on Windows; 0 elsewhere makes the OR a no-op.
CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


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
