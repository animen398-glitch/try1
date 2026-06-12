"""Tests for the TTL scan cache."""

from utils import scan_cache
from utils.scan_cache import TTLCache


def test_set_get_round_trip():
    c = TTLCache(ttl_seconds=100)
    c.set("k", {"v": 1})
    assert c.get("k") == {"v": 1}
    assert len(c) == 1


def test_missing_key_returns_none():
    assert TTLCache().get("nope") is None


def test_none_is_not_cached():
    c = TTLCache()
    c.set("k", None)
    assert c.get("k") is None
    assert len(c) == 0


def test_expiry(monkeypatch):
    t = [1000.0]
    monkeypatch.setattr(scan_cache.time, "time", lambda: t[0])
    c = TTLCache(ttl_seconds=10)
    c.set("k", "v")
    assert c.get("k") == "v"
    t[0] += 11                       # past TTL
    assert c.get("k") is None
    assert len(c) == 0               # expired entry pruned on access


def test_get_or_compute_computes_once():
    c = TTLCache()
    calls = []

    def fn():
        calls.append(1)
        return "computed"

    assert c.get_or_compute("k", fn) == "computed"
    assert c.get_or_compute("k", fn) == "computed"
    assert len(calls) == 1           # second call served from cache


def test_max_entries_eviction():
    c = TTLCache(ttl_seconds=100, max_entries=2)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)                    # evicts the oldest-expiring entry
    assert len(c) == 2


def test_clear():
    c = TTLCache()
    c.set("a", 1)
    c.clear()
    assert len(c) == 0
