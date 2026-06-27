"""Tests for the shared CLI error/exit contract in ``core.cli_common``."""
import sys

import pytest

from core.cli_common import (EXIT_ERROR, EXIT_OK, CliError, configure_stdout,
                             run_main)


def test_run_main_returns_int():
    assert run_main(lambda argv: 0) == 0
    assert run_main(lambda argv: 1) == 1


def test_run_main_none_is_success():
    """A ``main`` that returns ``None`` (prints only) exits 0."""
    assert run_main(lambda argv: None) == EXIT_OK


def test_run_main_clierror_to_stderr(capsys):
    def main(argv):
        raise CliError('bad project')

    code = run_main(main)
    assert code == EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'error: bad project' in captured.err


def test_run_main_oserror_is_expected(capsys):
    def main(argv):
        raise FileNotFoundError('missing.json')

    code = run_main(main)
    assert code == EXIT_ERROR
    assert 'error:' in capsys.readouterr().err


def test_run_main_systemexit_propagates():
    def main(argv):
        sys.exit(3)

    with pytest.raises(SystemExit) as exc:
        run_main(main)
    assert exc.value.code == 3


def test_run_main_unexpected_not_swallowed():
    """A programming bug (ValueError) is not masked — it still raises."""
    def main(argv):
        raise ValueError('boom')

    with pytest.raises(ValueError):
        run_main(main)


def test_run_main_passes_argv():
    seen = {}

    def main(argv):
        seen['argv'] = argv
        return 0

    run_main(main, ['a', 'b'])
    assert seen['argv'] == ['a', 'b']


def test_configure_stdout_no_raise():
    configure_stdout()  # under capture this is a no-op; must not raise


def test_configure_stdout_handles_missing_reconfigure(monkeypatch):
    class _Dumb:
        pass

    monkeypatch.setattr(sys, 'stdout', _Dumb())
    configure_stdout()  # AttributeError swallowed
