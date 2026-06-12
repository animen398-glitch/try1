"""Tests for the RateLimiter (deterministic via an injected fake clock)."""

from utils.rate_limiter import RateLimiter


class _FakeClock:
    def __init__(self):
        self.t = 0.0

    def time(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_disabled_when_rate_non_positive():
    rl = RateLimiter(0)
    assert rl.enabled is False
    assert rl.acquire() == 0.0


def test_enforces_interval_across_calls():
    clk = _FakeClock()
    rl = RateLimiter(10, time_fn=clk.time, sleep_fn=clk.sleep)  # 0.1s interval
    assert rl.enabled is True
    assert rl.acquire() == 0.0          # first call: no wait
    assert round(rl.acquire(), 5) == 0.1  # must wait one interval
    assert round(rl.acquire(), 5) == 0.1  # and again
    assert round(clk.t, 5) == 0.2       # clock advanced by the slept time


def test_no_wait_when_caller_already_slow():
    clk = _FakeClock()
    rl = RateLimiter(5, time_fn=clk.time, sleep_fn=clk.sleep)  # 0.2s interval
    rl.acquire()
    clk.t += 1.0                         # caller idled longer than the interval
    assert rl.acquire() == 0.0           # so no throttling needed
