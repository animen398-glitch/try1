"""utils/host_throttle.py

Per-host outbound request throttle (WS6 / Opt-5). Enforces a scan's scope
``rate_limit`` — historically *metadata only* — by spacing requests to each
target host, so every recon/audit engine (they all funnel HTTP through
``utils.http_retry``) and the concurrent WS3 scan phases stay polite to a single
host.

Installed at the ``utils.http_retry`` seam via ``set_host_throttle`` for the
duration of a scan; a rate of ``0``/``None`` disables it (``acquire`` is a
no-op), so the default (no scope rate limit) is byte-for-byte the old behaviour.
Thread-safe and clock-injectable — it reuses :class:`utils.rate_limiter.RateLimiter`
(one limiter per host) so a shared instance correctly serialises same-host
requests across the WS3 worker threads.
"""

import re
import time
import threading
from typing import Callable, Dict

from utils.rate_limiter import RateLimiter

__all__ = ['HostThrottle', 'rate_per_sec']

_NUM = re.compile(r'[\d.]+')


def rate_per_sec(spec) -> float:
    """Parse a scope ``rate_limit`` spec into requests/second.

    Accepts a bare number (``2`` / ``"2"`` → 2/s), ``"N rps"`` / ``"N/s"`` (→ N/s)
    or ``"N/min"`` / ``"N per minute"`` (→ N/60). ``None`` / unparseable → ``0.0``
    (throttling disabled)."""
    if spec is None:
        return 0.0
    if isinstance(spec, (int, float)):
        return max(0.0, float(spec))
    s = str(spec).lower()
    m = _NUM.search(s)
    if not m:
        return 0.0
    n = max(0.0, float(m.group()))
    if 'min' in s or 'hour' in s:
        return n / (3600.0 if 'hour' in s else 60.0)
    return n


class HostThrottle:
    """A registry of per-host :class:`RateLimiter`s.

    ``acquire(host)`` blocks until the next request to ``host`` is allowed and
    returns the seconds slept. A non-positive rate disables it. ``time_fn`` /
    ``sleep_fn`` are injectable so the spacing is unit-tested without real time."""

    def __init__(self, rate: float,
                 time_fn: Callable[[], float] = time.monotonic,
                 sleep_fn: Callable[[float], None] = time.sleep):
        self._rate = float(rate or 0.0)
        self._time_fn = time_fn
        self._sleep_fn = sleep_fn
        self._lock = threading.Lock()
        self._by_host: Dict[str, RateLimiter] = {}

    @property
    def enabled(self) -> bool:
        return self._rate > 0.0

    def acquire(self, host: str) -> float:
        if not self.enabled or not host:
            return 0.0
        with self._lock:
            limiter = self._by_host.get(host)
            if limiter is None:
                limiter = RateLimiter(self._rate, time_fn=self._time_fn,
                                      sleep_fn=self._sleep_fn)
                self._by_host[host] = limiter
        return limiter.acquire()
