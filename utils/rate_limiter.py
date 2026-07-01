"""utils/rate_limiter.py
Thread-safe rate limiter for being polite when many worker threads hit the
network at once (DNS brute-force, subdomain liveness probes, …).

Enforces a minimum interval between ``acquire()`` calls across all threads.
The clock and sleep functions are injectable so the spacing logic can be
unit-tested deterministically without real time. ``rate_per_sec <= 0`` disables
limiting (acquire is a no-op).
"""

import threading
import time
from typing import Callable


class RateLimiter:
    def __init__(self, rate_per_sec: float,
                 time_fn: Callable[[], float] = time.monotonic,
                 sleep_fn: Callable[[float], None] = time.sleep):
        self._interval = 1.0 / rate_per_sec if rate_per_sec and rate_per_sec > 0 else 0.0
        self._time = time_fn
        self._sleep = sleep_fn
        self._lock = threading.Lock()
        self._next = 0.0

    @property
    def enabled(self) -> bool:
        return self._interval > 0.0

    def acquire(self) -> float:
        """Block until the next call is allowed; return seconds actually slept."""
        if self._interval <= 0.0:
            return 0.0
        with self._lock:
            now = self._time()
            wait = self._next - now
            if wait > 0:
                self._sleep(wait)
                now = self._time()
            else:
                wait = 0.0
            # Schedule the next slot relative to the later of now / previous slot.
            self._next = max(now, self._next) + self._interval
            return wait


class RequestThrottle:
    """Per-key fixed-window request throttle for the LAN web console.

    Unlike :class:`RateLimiter` (which *blocks* to pace outbound requests), this
    is a **non-blocking** server-side guard: ``allow(key)`` returns ``False``
    once ``key`` (a token, or a client IP) exceeds ``max_requests`` within
    ``window_sec`` — the caller then replies HTTP 429 instead of doing the work.
    ``max_requests <= 0`` (or a non-positive window) disables throttling.
    Thread-safe; ``time_fn`` is injectable so the window logic tests without
    real time."""

    def __init__(self, max_requests: int, window_sec: float,
                 time_fn: Callable[[], float] = time.monotonic):
        self._max = int(max_requests)
        self._window = float(window_sec)
        self._time = time_fn
        self._lock = threading.Lock()
        self._hits: dict = {}   # key -> [window_start, count]

    @property
    def enabled(self) -> bool:
        return self._max > 0 and self._window > 0.0

    @property
    def limit(self) -> int:
        """Max requests allowed per window (0 = disabled)."""
        return self._max

    def allow(self, key: str) -> bool:
        """Record a hit for ``key``; return whether it is within the limit."""
        if not self.enabled:
            return True
        now = self._time()
        with self._lock:
            start, count = self._hits.get(key, (now, 0))
            if now - start >= self._window:      # window elapsed → reset
                start, count = now, 0
            count += 1
            self._hits[key] = (start, count)
            if len(self._hits) > 1024:           # bound memory: drop stale keys
                for k in [k for k, (s, _) in self._hits.items()
                          if now - s >= self._window]:
                    self._hits.pop(k, None)
            return count <= self._max
