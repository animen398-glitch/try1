"""core/crash_reporter.py — local-first crash reporting (offline)."""

import json

import pytest

from core import crash_reporter as cr


@pytest.fixture
def crash_dir(tmp_path, monkeypatch):
    """Point the reporter at an isolated crash directory and clear breadcrumbs."""
    d = tmp_path / 'crashes'
    d.mkdir()
    monkeypatch.setattr(cr, '_crash_dir', lambda: d)
    cr._BREADCRUMBS.clear()
    return d


# ── redaction ──────────────────────────────────────────────────────────────

def test_redact_strips_headers_and_tokens():
    red = cr._redact(
        "Authorization: Bearer sk-abc123\n"
        "Cookie: session=deadbeef; csrf=xyz\n"
        "api_key=supersecret12345\n"
        "url http://x/?token=leak&user=bob")
    assert 'sk-abc123' not in red
    assert 'deadbeef' not in red
    assert 'supersecret12345' not in red
    assert 'leak' not in red
    assert 'REDACTED' in red
    assert 'user=bob'.split('=')[0] in red  # non-secret key name survives


def test_redact_jwt():
    jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF_-123'
    assert jwt not in cr._redact(f'token was {jwt} end')


def test_redact_leaves_plain_text():
    plain = 'Traceback: ValueError at collection_runner.py line 42'
    assert cr._redact(plain) == plain


# ── report I/O ─────────────────────────────────────────────────────────────

def test_report_exception_writes_valid_json(crash_dir):
    try:
        raise ValueError('boom in worker')
    except ValueError as e:
        path = cr.report_exception(e, kind='worker')

    assert path is not None and path.exists()
    data = json.loads(path.read_text(encoding='utf-8'))
    for key in ('kind', 'time', 'app_version', 'os', 'python', 'qt',
                'detail', 'breadcrumbs'):
        assert key in data
    assert data['kind'] == 'worker'
    assert 'boom in worker' in data['detail']
    assert 'ValueError' in data['detail']


def test_report_detail_is_redacted(crash_dir):
    try:
        raise RuntimeError('failed with Authorization: Bearer sk-topsecret999')
    except RuntimeError as e:
        path = cr.report_exception(e)
    data = json.loads(path.read_text(encoding='utf-8'))
    assert 'sk-topsecret999' not in data['detail']
    assert 'REDACTED' in data['detail']


# ── breadcrumbs ────────────────────────────────────────────────────────────

def test_breadcrumbs_bounded(crash_dir):
    for i in range(80):
        cr.breadcrumb(f'action {i}')
    crumbs = cr.breadcrumbs()
    assert len(crumbs) == 50            # deque(maxlen=50)
    assert 'action 79' in crumbs[-1]
    assert not any('action 0' == c.split()[-1] for c in crumbs)  # oldest evicted


def test_note_swallowed_records_observable_breadcrumb(crash_dir):
    try:
        raise OSError('disk full')
    except OSError as e:
        cr.note_swallowed('history snapshot write', e)
    crumbs = cr.breadcrumbs()
    assert any('swallowed history snapshot write' in c and 'OSError' in c
               and 'disk full' in c for c in crumbs)


def test_note_swallowed_never_raises_and_redacts(crash_dir):
    # Must be safe to call from a bare best-effort except and must redact.
    cr.note_swallowed('auth', ValueError('authorization: Bearer hush123'))
    assert 'hush123' not in ' '.join(cr.breadcrumbs())


def test_breadcrumbs_redacted_and_attached(crash_dir):
    cr.breadcrumb('open url http://x/?token=hush123')
    try:
        raise ValueError('x')
    except ValueError as e:
        path = cr.report_exception(e)
    data = json.loads(path.read_text(encoding='utf-8'))
    assert data['breadcrumbs']
    assert 'hush123' not in ' '.join(data['breadcrumbs'])


# ── pending / seen ─────────────────────────────────────────────────────────

def test_pending_and_mark_seen(crash_dir):
    assert cr.pending_crashes() == []
    try:
        raise ValueError('one')
    except ValueError as e:
        cr.report_exception(e)

    pending = cr.pending_crashes()
    assert len(pending) == 1
    assert pending[0]['_path']

    cr.mark_seen(pending)
    assert cr.pending_crashes() == []   # marker suppresses it


# ── hooks chain (never swallow) ────────────────────────────────────────────

def test_excepthook_writes_and_chains(crash_dir, monkeypatch):
    called = []
    monkeypatch.setattr(cr, '_orig_excepthook', lambda *a: called.append(a))
    try:
        raise KeyError('main-thread boom')
    except KeyError as e:
        cr._excepthook(type(e), e, e.__traceback__)

    assert len(cr.pending_crashes()) == 1        # report written
    assert len(called) == 1                       # original hook still called


def test_threading_excepthook_writes_and_chains(crash_dir, monkeypatch):
    called = []
    monkeypatch.setattr(cr, '_orig_threading_hook', lambda a: called.append(a))

    class _Args:
        exc_type = RuntimeError
        exc_value = RuntimeError('thread boom')
        exc_traceback = None
        thread = None

    cr._threading_excepthook(_Args())
    assert len(cr.pending_crashes()) == 1
    assert len(called) == 1


# ── send (opt-in, https-only) ──────────────────────────────────────────────

def test_send_report_refuses_without_endpoint():
    ok, msg = cr.send_report({'kind': 'x'}, '')
    assert ok is False


def test_send_report_refuses_non_https():
    ok, msg = cr.send_report({'kind': 'x'}, 'http://insecure.example')
    assert ok is False
    assert 'https' in msg.lower()
