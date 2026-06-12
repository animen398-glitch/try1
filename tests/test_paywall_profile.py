"""PaywallBypass honours the configured UA profile for its base requests.

The profile sets the base headers (so referer/cache/AMP/wayback strategies
browse as the chosen browser), while a per-strategy ua= override (the Googlebot
spoof) still wins for that one request.
"""

import core.paywall_bypass as pb


def _capture_ua(monkeypatch):
    seen = {}

    def fake_urlopen_retry(req, timeout, **kw):
        seen["ua"] = req.get_header("User-agent")
        return b"", {}

    monkeypatch.setattr(pb, "urlopen_retry", fake_urlopen_retry)
    return seen


def test_profile_sets_base_user_agent(monkeypatch):
    seen = _capture_ua(monkeypatch)
    bp = pb.PaywallBypass()
    bp.configure(profile="firefox_windows")
    bp._fetch_raw("https://x.com")
    assert "Firefox" in seen["ua"]


def test_default_profile_is_chrome(monkeypatch):
    seen = _capture_ua(monkeypatch)
    bp = pb.PaywallBypass()
    bp.configure()
    bp._fetch_raw("https://x.com")
    assert "Chrome" in seen["ua"]


def test_explicit_ua_overrides_profile(monkeypatch):
    seen = _capture_ua(monkeypatch)
    bp = pb.PaywallBypass()
    bp.configure(profile="firefox_windows")
    bp._fetch_raw("https://x.com", ua="Mozilla/5.0 (compatible; Googlebot/2.1)")
    assert "Googlebot" in seen["ua"]


def test_unknown_profile_falls_back(monkeypatch):
    seen = _capture_ua(monkeypatch)
    bp = pb.PaywallBypass()
    bp.configure(profile="does_not_exist")
    bp._fetch_raw("https://x.com")
    # SessionBuilder falls back to chrome_windows for an unknown profile.
    assert "Chrome" in seen["ua"]
