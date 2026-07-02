"""utils/http_retry.py

Retry transient HTTP failures with exponential backoff + jitter.

The recon stack talks to flaky, rate-limited third-party services (ip-api.com,
crt.sh, HackerTarget, AlienVault, Anubis, archive.org, Google cache). A single
transient blip or an HTTP 429 used to mean "silently return nothing"; this wraps
a urlopen-style call so those are retried a few times before giving up, while
permanent errors (404, parse errors) fail fast.

Pure and side-effect-light: the sleep and RNG are injectable, so the backoff
logic is unit-tested deterministically without real delays or network — the same
pattern as utils.rate_limiter.
"""

import gzip
import random
import socket
import time
import urllib.error
import urllib.request
import zlib
from typing import Callable, Optional

# Optional per-host throttle hook (WS6 / Opt-5). A scan installs a
# ``HostThrottle.acquire`` via :func:`set_host_throttle`; ``urlopen_retry`` then
# spaces every attempt per target host so all engines that use this seam honour
# the scope rate limit. Default ``None`` → no-op (old behaviour preserved).
_HOST_THROTTLE: Optional[Callable[[str], float]] = None


def set_host_throttle(fn: Optional[Callable[[str], float]]) -> None:
    """Install (or clear, with ``None``) the per-host throttle used by
    :func:`urlopen_retry`. Scan-scoped: the caller sets it at scan start and
    clears it in a ``finally``."""
    global _HOST_THROTTLE
    _HOST_THROTTLE = fn


# Statuses worth retrying: rate-limit + transient upstream/server errors.
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
# Cap a server-provided Retry-After so a hostile/huge value can't stall a scan.
_MAX_RETRY_AFTER = 30.0


def is_transient(exc: BaseException) -> bool:
    """True for errors worth retrying (rate-limit / transient / timeout)."""
    # HTTPError is a subclass of URLError — check it first for the status code.
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _RETRY_STATUS
    if isinstance(exc, urllib.error.URLError):
        return True
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    return False


def _retry_after_seconds(exc: BaseException) -> Optional[float]:
    """Honour a server ``Retry-After: <seconds>`` header when present."""
    if isinstance(exc, urllib.error.HTTPError) and exc.headers:
        raw = exc.headers.get('Retry-After')
        if raw:
            try:
                return max(0.0, min(_MAX_RETRY_AFTER, float(raw)))
            except (TypeError, ValueError):
                return None  # HTTP-date form is not worth parsing here
    return None


def retry(fn: Callable, *, attempts: int = 3, base_delay: float = 0.5,
          max_delay: float = 8.0, sleep: Callable[[float], None] = time.sleep,
          rng: Callable[[], float] = random.random,
          retry_on: Callable[[BaseException], bool] = is_transient):
    """Call ``fn()`` with retries on transient failures.

    Backoff is exponential (``base_delay * 2**i``) with full jitter, capped at
    ``max_delay``; a server ``Retry-After`` overrides the computed delay. A
    non-transient error (per ``retry_on``) or the final attempt re-raises
    immediately. ``sleep``/``rng`` are injectable for tests.
    """
    if attempts < 1:
        raise ValueError('attempts must be >= 1')
    last: Optional[BaseException] = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — re-raised unless transient
            last = e
            if i == attempts - 1 or not retry_on(e):
                raise
            server = _retry_after_seconds(e)
            if server is not None:
                delay = server
            else:
                delay = min(max_delay, base_delay * (2 ** i)) * (0.5 + rng())
            sleep(delay)
    raise last  # pragma: no cover — loop always returns or raises


def urlopen_retry(req, timeout: float, *, return_final_url: bool = False, **kw):
    """GET ``req`` with retry; return ``(body_bytes, response_headers)``.

    With ``return_final_url=True`` the tuple gains a third element — the final URL
    after any redirects (``response.geturl()``) — so callers can tell e.g. that an
    ``http://`` request was redirected to ``https://``. Default off, so existing
    two-tuple callers are unaffected.

    The response is read fully inside each attempt (a connection can't be
    retried once consumed). Extra kwargs pass through to :func:`retry`.
    """
    def _once():
        throttle = _HOST_THROTTLE
        if throttle is not None:
            try:
                throttle(getattr(req, 'host', '') or '')
            except Exception:
                pass   # a misbehaving throttle must never break a fetch
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if return_final_url:
                return r.read(), r.headers, r.geturl()
            return r.read(), r.headers
    return retry(_once, **kw)


def decompress(raw: bytes, headers) -> bytes:
    """Decompress a response body per its Content-Encoding (gzip/deflate).

    urllib never auto-decompresses, so any caller that sends
    ``Accept-Encoding: gzip`` (e.g. SessionBuilder) MUST run the body through
    this or it will try to parse compressed bytes. Falls back to the magic
    number when the header is missing, and returns ``raw`` unchanged on any
    failure or unknown encoding.
    """
    try:
        enc = (headers.get('Content-Encoding') or '').lower().strip()
    except Exception:
        enc = ''
    try:
        if enc == 'gzip' or raw[:2] == b'\x1f\x8b':
            return gzip.decompress(raw)
        if enc == 'deflate':
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        pass
    return raw


def urlopen_text(req, timeout: float, *, encoding: str = 'utf-8',
                 errors: str = 'ignore', **kw) -> str:
    """GET ``req`` with retry, decompress, and decode to text.

    The gzip-aware convenience used by callers that build requests via
    SessionBuilder (which advertises gzip). Extra kwargs pass to :func:`retry`.
    """
    raw, headers = urlopen_retry(req, timeout, **kw)
    return decompress(raw, headers).decode(encoding, errors)
