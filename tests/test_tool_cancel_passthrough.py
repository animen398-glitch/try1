"""tests/test_tool_cancel_passthrough.py

The optional cooperative-cancellation seam on the external-tool runners:
``set_cancel_event`` must forward the token into the command runner, and the
default (no token) path must keep the classic ``(cmd, timeout)`` call so existing
injected test doubles stay valid. Offline — the runner is stubbed.
"""

from core import external_tools as ext
from core.bbot_adapter import BBOTRunner
from core.external_tools import KatanaRunner, NucleiRunner
from utils.subprocess_utils import CancellationToken


def test_nuclei_forwards_cancel_event(monkeypatch):
    seen = {}

    def fake_run_command(cmd, timeout, **kw):
        seen['kw'] = kw
        return {'rc': 0, 'stdout': '', 'stderr': '', 'timed_out': False,
                'cancelled': False, 'truncated': False}

    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command', fake_run_command)

    runner = NucleiRunner()
    tok = CancellationToken()
    runner.set_cancel_event(tok)
    runner.scan('https://example.com')
    assert seen['kw'].get('cancel_event') is tok


def test_default_path_omits_cancel_event(monkeypatch):
    """Without a token, no ``cancel_event`` kwarg is passed (backward compat)."""
    seen = {}

    def fake_run_command(cmd, timeout, **kw):
        seen['kw'] = kw
        return {'rc': 0, 'stdout': '', 'stderr': '', 'timed_out': False,
                'cancelled': False, 'truncated': False}

    monkeypatch.setattr(KatanaRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command', fake_run_command)

    KatanaRunner().crawl('https://example.com')
    assert 'cancel_event' not in seen['kw']


def test_bbot_injected_runner_receives_cancel_event():
    seen = {}

    def fake_runner(cmd, timeout, **kw):
        seen['kw'] = kw
        return {'rc': 0, 'stdout': '', 'stderr': '', 'timed_out': False,
                'cancelled': False, 'truncated': False}

    runner = BBOTRunner(runner=fake_runner, detector=lambda: True)
    tok = CancellationToken()
    runner.set_cancel_event(tok)
    runner.run('example.com')
    assert seen['kw'].get('cancel_event') is tok


def test_bbot_default_runner_call_is_two_positional():
    """A bare (cmd, timeout) runner still works when no token is set."""
    calls = {}

    def two_arg_runner(cmd, timeout):
        calls['ok'] = True
        return {'rc': 0, 'stdout': '', 'stderr': '', 'timed_out': False,
                'cancelled': False, 'truncated': False}

    runner = BBOTRunner(runner=two_arg_runner, detector=lambda: True)
    runner.run('example.com')
    assert calls.get('ok') is True
