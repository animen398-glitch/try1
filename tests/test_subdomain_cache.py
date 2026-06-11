"""Tests for passive-source caching in SubdomainScanner (network-free).

The crt.sh / HackerTarget fetches are stubbed; we assert the TTL cache spares
repeat network calls within a session and that ``use_cache=False`` bypasses it.
"""

import core.subdomain_scanner as ss
from core.subdomain_scanner import SubdomainScanner


def _no_dns(monkeypatch):
    # Keep scans fully offline: every name "resolves" to a fixed IP.
    monkeypatch.setattr(ss.socket, "gethostbyname", lambda host: "1.2.3.4")


def _passive_only(scanner, domain, **kw):
    return scanner.scan(domain, passive=True, brute=False, active=False, **kw)


def test_passive_results_recorded(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh",
                        staticmethod(lambda d: ["api.example.com", "example.com"]))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: [("mail.example.com", "9.9.9.9")]))

    res = _passive_only(SubdomainScanner(), "example.com")
    subs = {e["subdomain"] for e in res["results"]}
    assert subs == {"api.example.com", "example.com", "mail.example.com"}


def test_second_scan_uses_cache(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    crt_calls, ht_calls = [], []
    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh",
                        staticmethod(lambda d: crt_calls.append(d) or ["a.example.com"]))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: ht_calls.append(d) or []))

    scanner = SubdomainScanner()
    _passive_only(scanner, "example.com")
    _passive_only(scanner, "example.com")

    assert crt_calls == ["example.com"]   # fetched once, second scan cached
    assert ht_calls == ["example.com"]


def test_use_cache_false_refetches(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    crt_calls = []
    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh",
                        staticmethod(lambda d: crt_calls.append(d) or ["a.example.com"]))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: []))

    scanner = SubdomainScanner()
    _passive_only(scanner, "example.com", use_cache=False)
    _passive_only(scanner, "example.com", use_cache=False)

    assert crt_calls == ["example.com", "example.com"]   # cache bypassed


def test_fetch_failure_is_swallowed_and_not_cached(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    calls = []

    def boom(d):
        calls.append(d)
        raise RuntimeError("network down")

    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh", staticmethod(boom))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: []))

    scanner = SubdomainScanner()
    res = _passive_only(scanner, "example.com")
    assert res["status"] == "Success"
    assert res["results"] == []
    # A failed fetch must not poison the cache — a retry should fetch again.
    _passive_only(scanner, "example.com")
    assert calls == ["example.com", "example.com"]
