import logging
import re

from core.paths import get_path_manager


def _log_file() -> str:
    """Absolute path to the system log under the writable data root.

    Resolved through PathManager (not a hardcoded ``data/system.log`` relative
    to the CWD) so a frozen .exe logs under %APPDATA% instead of next to the
    executable / the ephemeral _MEIPASS dir. ``get_db_path`` also ensures the
    parent ``data/`` directory exists.
    """
    return str(get_path_manager().get_db_path('system.log'))


def get_logger(name):
    log_file = _log_file()
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.FileHandler(log_file, encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def get_last_logs(limit=50):
    import os
    log_file = _log_file()
    if not os.path.exists(log_file):
        return []
    with open(log_file, 'r', encoding='utf-8') as f:
        return f.readlines()[-limit:]


# ── external tool-run journal ────────────────────────────────────────────────
#
# One redacted, structured line per external-tool run, written to the SAME
# system log the System tab already shows (get_logger) — not a second, competing
# logging system. Every value is scrubbed of credentials/secrets before it is
# written (reuses the crash-reporter redaction), and nothing here ever raises.

# Flag tokens whose *following* argument carries a secret and must be hidden
# (e.g. ``--api-key SECRET`` — the value is a separate argv token, so the generic
# key=value redaction can't catch it).
_SENSITIVE_ARG_HINT = re.compile(
    r'(?i)(api[_-]?key|token|secret|password|passwd|pwd|credential|cookie|auth)')


def redact_command(cmd) -> str:
    """Turn a command (list or string) into a safe, redacted single line.

    Scrubs inline secrets in each token (``key=value``, ``Bearer …``, JWTs, URL
    query values) and blanks the value that follows a sensitive flag. Never
    raises — a formatting problem must not break logging.
    """
    try:
        from core import crash_reporter
        if isinstance(cmd, str):
            return crash_reporter.redact(cmd)
        out, redact_next = [], False
        for raw in (cmd or []):
            tok = str(raw)
            if redact_next:
                out.append('***REDACTED***')
                redact_next = False
                continue
            out.append(crash_reporter.redact(tok))
            if tok.startswith('-') and _SENSITIVE_ARG_HINT.search(tok):
                redact_next = True
        return ' '.join(out)
    except Exception:
        return '***'


def _derive_tool_status(result) -> str:
    """Map a ``run_command``/``run_capture`` result dict to a journal status."""
    if not isinstance(result, dict):
        return 'unknown'
    if result.get('cancelled'):
        return 'cancelled'
    if result.get('timed_out'):
        return 'timeout'
    if result.get('error'):
        return 'error'
    rc = result.get('rc')
    if rc not in (None, 0):
        return 'error'
    return 'success'


def journal_tool_run(tool, command, result=None, *, status=None,
                     duration_ms=None, logger=None) -> str:
    """Record one external-tool run in the system log (redacted, never raises).

    ``status`` (``running``/``success``/``error``/``timeout``/``cancelled``) is
    derived from ``result`` when not given. Returns the status used. ``logger`` is
    injectable for tests.
    """
    try:
        log = logger if logger is not None else get_logger('tool-run')
        st = status or _derive_tool_status(result)
        safe_cmd = redact_command(command)
        rc = result.get('rc') if isinstance(result, dict) else None
        rc_s = '' if rc is None else f' rc={rc}'
        dur_s = f' {int(duration_ms)}ms' if duration_ms is not None else ''
        tail = ''
        if isinstance(result, dict) and st in ('error', 'timeout'):
            from core import crash_reporter
            err = (result.get('stderr') or result.get('error') or '')
            err = crash_reporter.redact(str(err).strip().replace('\n', ' '))
            if err:
                tail = ' | ' + err[:300]
        log.info(f'[{tool}] {st}{rc_s}{dur_s} | {safe_cmd}{tail}')
        return st
    except Exception:
        return status or 'unknown'
