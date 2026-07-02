"""Tests for utils.host_throttle + its http_retry seam (offline, injected clock)."""

import urllib.request

from utils import http_retry
from utils.host_throttle import HostThrottle, rate_per_sec


def test_rate_per_sec_parses_specs():
    assert rate_per_sec(None) == 0.0
    assert rate_per_sec(2) == 2.0
    assert rate_per_sec("3") == 3.0
    assert rate_per_sec("5 rps") == 5.0
    assert rate_per_sec("10/s") == 10.0
    assert rate_per_sec("60/min") == 1.0
    assert rate_per_sec("120 per minute") == 2.0
    assert rate_per_sec("3600/hour") == 1.0
    assert rate_per_sec("nonsense") == 0.0


def test_disabled_when_rate_non_positive():
    t = HostThrottle(0)
    assert t.enabled is False
    assert t.acquire("x") == 0.0


def _fake_clock():
    now = [0.0]
    slept = []

    def time_fn():
        return now[0]

    def sleep_fn(s):
        slept.append(s)
        now[0] += s

    return slept, time_fn, sleep_fn


def test_spaces_requests_per_host():
    slept, tf, sf = _fake_clock()
    t = HostThrottle(1.0, time_fn=tf, sleep_fn=sf)   # 1/s → 1s spacing
    assert t.acquire("a") == 0.0        # first request is free
    assert t.acquire("a") == 1.0        # second waits ~1s
    assert slept == [1.0]


def test_hosts_are_independent():
    slept, tf, sf = _fake_clock()
    t = HostThrottle(1.0, time_fn=tf, sleep_fn=sf)
    assert t.acquire("a") == 0.0
    assert t.acquire("b") == 0.0        # a different host has its own limiter
    assert slept == []


class _Resp:
    headers: dict = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return b'ok'


def test_urlopen_retry_calls_throttle_with_request_host(monkeypatch):
    seen = []
    monkeypatch.setattr(urllib.request, 'urlopen', lambda req, timeout: _Resp())
    http_retry.set_host_throttle(lambda host: seen.append(host) or 0.0)
    try:
        body, _ = http_retry.urlopen_retry(
            urllib.request.Request('https://example.com/path'), 5)
        assert body == b'ok'
        assert seen == ['example.com']
    finally:
        http_retry.set_host_throttle(None)


def test_urlopen_retry_without_throttle_is_noop(monkeypatch):
    monkeypatch.setattr(urllib.request, 'urlopen', lambda req, timeout: _Resp())
    http_retry.set_host_throttle(None)
    body, _ = http_retry.urlopen_retry(
        urllib.request.Request('https://example.com/'), 5)
    assert body == b'ok'                 # no hook installed → plain fetch
