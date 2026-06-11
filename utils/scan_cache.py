"""utils/scan_cache.py
A small thread-safe TTL cache for avoiding repeated network lookups within a
session (e.g. GeoIP for the same IP). Opt-in: callers decide what to cache.
Values are evicted when they expire or when the cache is full (oldest expiry
first). ``None`` is never cached (treated as "no value").
"""

import threading
import time
from typing import Any, Callable, Optional


class TTLCache:
    def __init__(self, ttl_seconds: float = 300, max_entries: int = 512):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._data: dict = {}              # key -> (expiry_ts, value)
        self._lock = threading.Lock()

    def get(self, key: Any) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expiry, value = item
            if time.time() >= expiry:
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: Any, value: Any) -> None:
        if value is None:
            return
        with self._lock:
            if key not in self._data and len(self._data) >= self._max:
                oldest = min(self._data, key=lambda k: self._data[k][0])
                self._data.pop(oldest, None)
            self._data[key] = (time.time() + self._ttl, value)

    def get_or_compute(self, key: Any, fn: Callable[[], Any]) -> Any:
        """Return the cached value for ``key`` or compute, store and return it."""
        cached = self.get(key)
        if cached is not None:
            return cached
        value = fn()
        self.set(key, value)
        return value

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
