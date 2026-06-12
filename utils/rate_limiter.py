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
