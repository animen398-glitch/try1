"""Tests for the RateLimiter (deterministic via an injected fake clock)."""

from utils.rate_limiter import RateLimiter, RequestThrottle


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


# ── RequestThrottle (server-side, non-blocking, per-key) ────────────────────

def test_throttle_disabled_when_non_positive():
    assert RequestThrottle(0, 60).enabled is False
    assert RequestThrottle(0, 60).allow('k') is True          # no-op → allow
    assert RequestThrottle(5, 0).enabled is False


def test_throttle_blocks_after_limit_per_key():
    clk = _FakeClock()
    t = RequestThrottle(3, 60.0, time_fn=clk.time)
    assert [t.allow('tok') for _ in range(3)] == [True, True, True]
    assert t.allow('tok') is False        # 4th within window → rejected
    assert t.allow('tok') is False


def test_throttle_is_per_key():
    clk = _FakeClock()
    t = RequestThrottle(1, 60.0, time_fn=clk.time)
    assert t.allow('a') is True
    assert t.allow('a') is False
    assert t.allow('b') is True           # a different key is independent


def test_throttle_window_resets():
    clk = _FakeClock()
    t = RequestThrottle(2, 60.0, time_fn=clk.time)
    assert t.allow('k') and t.allow('k')
    assert t.allow('k') is False
    clk.t += 60.0                          # window elapsed
    assert t.allow('k') is True            # budget refreshed
