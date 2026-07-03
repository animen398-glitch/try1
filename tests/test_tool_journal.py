"""tests/test_tool_journal.py

The external-tool run journal in ``utils.system_logger``: status derivation,
credential redaction of the command and error tail, and that a redacted line is
written to the (injectable) logger. Offline, no processes spawned.
"""

from utils.system_logger import (
    _derive_tool_status, journal_tool_run, redact_command,
)


class _FakeLogger:
    def __init__(self):
        self.lines = []

    def info(self, msg):
        self.lines.append(msg)


# ── status derivation ─────────────────────────────────────────────────────────

def test_status_success():
    assert _derive_tool_status({'rc': 0}) == 'success'


def test_status_error_from_rc():
    assert _derive_tool_status({'rc': 2}) == 'error'


def test_status_error_from_error_key():
    assert _derive_tool_status({'rc': None, 'error': 'boom'}) == 'error'


def test_status_timeout_and_cancelled():
    assert _derive_tool_status({'timed_out': True}) == 'timeout'
    assert _derive_tool_status({'cancelled': True}) == 'cancelled'
    # cancelled wins over a timeout flag (cancel is the operator's explicit act).
    assert _derive_tool_status({'cancelled': True, 'timed_out': True}) == 'cancelled'


# ── command redaction ─────────────────────────────────────────────────────────

def test_redact_command_hides_flag_value():
    cmd = ['nuclei', '-u', 'https://x', '-api-key', 'SECRETVALUE']
    out = redact_command(cmd)
    assert 'SECRETVALUE' not in out
    assert 'nuclei' in out and 'https://x' in out


def test_redact_command_hides_inline_secret_and_bearer():
    cmd = ['tool', '-H', 'Authorization: Bearer abc123', 'token=deadbeef']
    out = redact_command(cmd)
    assert 'abc123' not in out
    assert 'deadbeef' not in out


def test_redact_command_url_query_value():
    out = redact_command(['tool', 'https://x/?apikey=topsecret'])
    assert 'topsecret' not in out


def test_redact_command_string_input():
    assert 'SECRET' not in redact_command('curl -H "token: SECRET"')


# ── journal writing ───────────────────────────────────────────────────────────

def test_journal_writes_redacted_line():
    log = _FakeLogger()
    st = journal_tool_run('nuclei', ['nuclei', '-api-key', 'SEKRET'],
                          {'rc': 0, 'stdout': 'x'}, duration_ms=42, logger=log)
    assert st == 'success'
    assert len(log.lines) == 1
    line = log.lines[0]
    assert 'nuclei' in line and 'success' in line
    assert '42ms' in line and 'rc=0' in line
    assert 'SEKRET' not in line


def test_journal_error_includes_redacted_stderr_tail():
    log = _FakeLogger()
    st = journal_tool_run('amass', ['amass'],
                          {'rc': 2, 'stderr': 'failed token=abc'}, logger=log)
    assert st == 'error'
    assert 'abc' not in log.lines[0]      # stderr tail scrubbed


def test_journal_never_raises_on_bad_input():
    # No logger, weird result — must return a status, not blow up.
    assert journal_tool_run('t', None, None) in (
        'unknown', 'success', 'error', 'timeout', 'cancelled')


def test_journal_status_override_running():
    log = _FakeLogger()
    st = journal_tool_run('scrapy', ['scrapy'], None, status='running', logger=log)
    assert st == 'running'
    assert 'running' in log.lines[0]
