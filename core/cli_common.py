"""Shared plumbing for the project's thin ``*_cli.py`` entrypoints.

Goal: one uniform, CI/automation-friendly error and exit contract instead of
each CLI re-implementing (slightly differently) stdout setup and error
handling.

Contract:

* :func:`configure_stdout` — make stdout tolerant of un-encodable characters
  (replaces the duplicated ``sys.stdout.reconfigure(errors='replace')`` idiom;
  a no-op where the stream cannot be reconfigured, e.g. under pytest capture).
* :class:`CliError` — raise for an *expected*, user-facing failure (bad input,
  missing project, IO error). :func:`run_main` turns it — and the common
  expected OS errors — into a clean ``error: <msg>`` on stderr plus a non-zero
  exit, instead of leaking a traceback. Genuine bugs still raise normally.
* :func:`run_main` only wraps the executable (``__main__``) path. In-process
  ``main(argv)`` keeps returning an int, so unit tests that call ``main([...])``
  directly are unaffected.
"""
import sys
from typing import Callable, Optional, Sequence

EXIT_OK = 0
EXIT_ERROR = 2  # argparse already uses 2 for usage errors; reuse for clean fails


class CliError(Exception):
    """An expected, user-facing CLI failure — no traceback should be shown."""


# Expected operational failures (vs programming bugs we *want* to see traced).
# OSError covers FileNotFoundError/NotADirectoryError/PermissionError/etc.
_EXPECTED = (CliError, OSError)


def configure_stdout() -> None:
    """Best-effort: stdout replaces un-encodable chars instead of raising.

    A legacy Windows console (cp1251) would otherwise raise ``UnicodeEncodeError``
    on output containing e.g. ``→`` or Cyrillic. No-op where the stream can't be
    reconfigured (older Python streams, captured stdout)."""
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass


def run_main(main: Callable[..., Optional[int]],
             argv: Optional[Sequence[str]] = None) -> int:
    """Run a CLI ``main`` for the ``__main__`` path under a uniform contract.

    Returns ``main``'s exit code (``None`` is treated as success). On an
    *expected* failure prints ``error: <msg>`` to stderr and returns
    :data:`EXIT_ERROR`. ``SystemExit`` (argparse, or an inner ``sys.exit``)
    propagates unchanged; unexpected exceptions are not swallowed."""
    try:
        code = main(argv)
    except _EXPECTED as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK if code is None else code
