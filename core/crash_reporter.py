"""core/crash_reporter.py — local-first crash reporting & observability.

Catches every class of failure the app can hit — an uncaught exception on the
main thread, an exception raised (and caught) inside a background worker, a
hard Qt/C++ fatal, and Qt's own warning/critical/fatal messages — and persists
a structured, **secret-redacted** JSON report under the writable data root
(``PathManager.get_crash_dir()``). The next launch surfaces any unseen report
so the user can view / copy / (optionally) send it.

Design invariants:
  * **Local-first.** A report is only ever *written to disk*. Nothing is sent
    anywhere unless the user explicitly asks and a ``crash_reporting.endpoint``
    is configured — this keeps the offline/privacy positioning intact.
  * **Never swallow.** ``sys.excepthook`` / ``threading.excepthook`` write the
    report and then chain to the original hook, so behaviour is unchanged apart
    from the extra report.
  * **Import-light / headless-safe.** Qt is only touched inside ``install()``
    and the Qt message handler it registers, so importing this module (e.g. in
    tests) never pulls in a GUI binding.
"""

from __future__ import annotations

import faulthandler
import json
import os
import platform
import re
import sys
import threading
import traceback
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Ring buffer of the last user/GUI actions, attached to every report so a crash
# has context ("what was happening"). Bounded so it can never grow unbounded.
_BREADCRUMBS: "deque[str]" = deque(maxlen=50)

_installed = False
_orig_excepthook = None
_orig_threading_hook = None
# Kept alive for the whole process: faulthandler needs a live file object to
# dump a native (segfault) traceback into on a hard crash.
_faulthandler_fp = None

# Report file naming: crash-<utc>-<pid>-<seq>.json; a sibling ``<name>.seen``
# marker means the user has already been shown it.
_REPORT_GLOB = 'crash-*.json'
_SEEN_SUFFIX = '.seen'
_seq = 0


# --------------------------------------------------------------- redaction

# (pattern, replacement) pairs applied to any text before it is written or
# shown. This scrubs credentials that can legitimately appear in a traceback
# frame (a request URL, a header dict, a config value) so a crash report never
# leaks a secret. Ordered from most specific to most general.
_REDACTIONS = [
    # Header-style values that span spaces/semicolons (Authorization: Bearer …,
    # Cookie: a=1; b=2) — scrub the whole value to end of line so no token or
    # cookie pair leaks. (?i) + no DOTALL, so ``.*`` stops at the newline.
    (re.compile(r'(?i)\b(authorization|cookie|set-cookie)\b(\s*[:=]\s*).*'),
     r'\1\2***REDACTED***'),
    # Single-token secrets as key: value / key=value (value = one run, no space).
    (re.compile(
        r'(?i)\b(x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|'
        r'token|secret|client[_-]?secret|password|passwd|pwd)\b'
        r'(\s*[:=]\s*)(["\']?)[^"\'\s,;)}&]+'),
     r'\1\2\3***REDACTED***'),
    # "Bearer <token>" standalone (not already caught as a header value).
    (re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._\-]+'), 'Bearer ***REDACTED***'),
    # JWTs (three base64url segments) standalone.
    (re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
     '***REDACTED_JWT***'),
    # URL query-string values (keep the key, scrub the value).
    (re.compile(r'([?&][^=&\s]+=)[^&\s"\']+'), r'\1***'),
]


def _redact(text: str) -> str:
    """Scrub credentials/tokens/cookies from ``text`` before persist/display."""
    if not text:
        return text
    out = text
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    return out


# --------------------------------------------------------------- breadcrumbs

def breadcrumb(msg: str) -> None:
    """Record a short, human-readable action for the crash context trail.

    Cheap and best-effort — never raises, so call sites can drop it in freely
    (tab change, scan start, project open, …)."""
    try:
        ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
        _BREADCRUMBS.append(f'{ts} {_redact(str(msg))}')
    except Exception:
        pass


def breadcrumbs() -> List[str]:
    """Snapshot of the current breadcrumb trail (oldest first)."""
    return list(_BREADCRUMBS)


# --------------------------------------------------------------- report I/O

def _app_version() -> str:
    try:
        from core.config import APP_VERSION
        return APP_VERSION
    except Exception:
        return 'unknown'


def _qt_version() -> str:
    try:
        from qtpy.QtCore import __version__ as qt_version
        return str(qt_version)
    except Exception:
        return 'unavailable'


def _crash_dir() -> Optional[Path]:
    try:
        from core.paths import get_path_manager
        return get_path_manager().get_crash_dir()
    except Exception:
        return None


def _write_report(kind: str, detail: str) -> Optional[Path]:
    """Persist one redacted crash report as JSON; return its path (or None).

    Best-effort: a failure to write a crash report must never itself crash the
    process, so every step is guarded."""
    global _seq
    crash_dir = _crash_dir()
    if crash_dir is None:
        return None
    try:
        report = {
            'kind': kind,
            'time': datetime.now(timezone.utc).isoformat(),
            'app_version': _app_version(),
            'os': f'{platform.system()} {platform.release()}',
            'python': platform.python_version(),
            'qt': _qt_version(),
            'detail': _redact(detail or ''),
            'breadcrumbs': breadcrumbs(),
        }
        _seq += 1
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        name = f'crash-{stamp}-{os.getpid()}-{_seq}.json'
        path = crash_dir / name
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                        encoding='utf-8')
        return path
    except Exception:
        return None


def report_exception(exc: BaseException, *, kind: str = 'exception') -> Optional[Path]:
    """Write a report for an already-caught exception (e.g. from a worker).

    Must be called from inside the ``except`` block (or with a live
    ``__traceback__``) so the traceback is still attached."""
    try:
        detail = ''.join(
            traceback.format_exception(type(exc), exc, exc.__traceback__))
    except Exception:
        detail = repr(exc)
    return _write_report(kind, detail)


def pending_crashes() -> List[dict]:
    """Unseen crash reports (each with an added ``_path``), oldest first."""
    crash_dir = _crash_dir()
    if crash_dir is None:
        return []
    out: List[dict] = []
    try:
        for path in sorted(crash_dir.glob(_REPORT_GLOB)):
            if path.with_name(path.name + _SEEN_SUFFIX).exists():
                continue
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                data = {'kind': 'unreadable', 'detail': ''}
            data['_path'] = str(path)
            out.append(data)
    except Exception:
        return out
    return out


def send_report(report: dict, endpoint: str, *, timeout: float = 10.0):
    """POST a (already-redacted) report to an HTTPS endpoint. Opt-in only.

    Returns ``(ok, message)``. Never raises. Refuses non-HTTPS endpoints so a
    report is never sent in the clear. The stored report is redacted at write
    time, so what is sent carries no secrets."""
    if not endpoint:
        return False, 'no endpoint configured'
    if not str(endpoint).lower().startswith('https://'):
        return False, 'endpoint must be https://'
    try:
        import urllib.request
        payload = {k: v for k, v in report.items() if k != '_path'}
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req = urllib.request.Request(
            endpoint, data=data, method='POST',
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300, f'HTTP {resp.status}'
    except Exception as e:  # noqa: BLE001 — sending must never crash the app
        return False, str(e)


def mark_seen(reports) -> None:
    """Mark the given reports (dicts with ``_path``, or paths) as seen so a
    later ``pending_crashes()`` no longer returns them."""
    for item in reports or ():
        raw = item.get('_path') if isinstance(item, dict) else item
        if not raw:
            continue
        try:
            marker = Path(str(raw) + _SEEN_SUFFIX)
            marker.write_text('', encoding='utf-8')
        except Exception:
            pass


# --------------------------------------------------------------- hooks

def _excepthook(exc_type, exc, tb) -> None:
    _write_report('uncaught', ''.join(
        traceback.format_exception(exc_type, exc, tb)))
    if _orig_excepthook is not None:
        _orig_excepthook(exc_type, exc, tb)


def _threading_excepthook(args) -> None:
    _write_report('thread', ''.join(traceback.format_exception(
        args.exc_type, args.exc_value, args.exc_traceback)))
    if _orig_threading_hook is not None:
        _orig_threading_hook(args)


def _qt_message_handler(mode, context, message) -> None:
    """Route Qt's own log stream into the crash trail.

    Warnings/criticals become breadcrumbs (context for a later crash); a fatal
    (qFatal, which aborts the process) is written as a full report first."""
    try:
        from qtpy.QtCore import QtMsgType
    except Exception:
        return
    text = str(message)
    if mode == QtMsgType.QtFatalMsg:
        _write_report('qt_fatal', text)
    else:
        breadcrumb(f'[qt] {text}')


def install(*, faulthandler_enabled: bool = True) -> None:
    """Install all crash hooks. Idempotent — safe to call once at startup.

    Order matters only in that this should run **before** ``QApplication`` is
    created so the Qt message handler is in place for the whole GUI lifetime.
    """
    global _installed, _orig_excepthook, _orig_threading_hook, _faulthandler_fp
    if _installed:
        return
    _installed = True

    _orig_excepthook = sys.excepthook
    sys.excepthook = _excepthook

    _orig_threading_hook = getattr(threading, 'excepthook', None)
    threading.excepthook = _threading_excepthook

    # Native (segfault / C++) traceback dump — needs a live file object kept for
    # the whole process lifetime.
    if faulthandler_enabled:
        try:
            crash_dir = _crash_dir()
            if crash_dir is not None:
                _faulthandler_fp = open(crash_dir / 'faulthandler.log', 'a',
                                        encoding='utf-8')
                faulthandler.enable(file=_faulthandler_fp)
        except Exception:
            pass

    # Qt message handler — optional (only if a Qt binding is importable).
    try:
        from qtpy.QtCore import qInstallMessageHandler
        qInstallMessageHandler(_qt_message_handler)
    except Exception:
        pass

