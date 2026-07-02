"""Tests for passive-source caching in SubdomainScanner (network-free).

The crt.sh / HackerTarget fetches are stubbed; we assert the TTL cache spares
repeat network calls within a session and that ``use_cache=False`` bypasses it.
"""

import json

import core.subdomain_scanner as ss
from core.subdomain_scanner import SubdomainScanner


def _no_dns(monkeypatch):
    # Keep scans fully offline: every name "resolves" to a fixed IP, and the
    # extra passive sources stay silent unless a test stubs them with data.
    monkeypatch.setattr(ss.socket, "gethostbyname", lambda host: "1.2.3.4")
    monkeypatch.setattr(SubdomainScanner, "_fetch_alienvault",
                        classmethod(lambda cls, d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_anubis",
                        classmethod(lambda cls, d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_certspotter",
                        classmethod(lambda cls, d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_urlscan",
                        classmethod(lambda cls, d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_rapiddns",
                        classmethod(lambda cls, d: []))


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


def test_extra_passive_sources_recorded_and_cached(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh",
                        staticmethod(lambda d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: []))
    av_calls, an_calls = [], []
    monkeypatch.setattr(SubdomainScanner, "_fetch_alienvault",
                        classmethod(lambda cls, d: av_calls.append(d) or ["av.example.com"]))
    monkeypatch.setattr(SubdomainScanner, "_fetch_anubis",
                        classmethod(lambda cls, d: an_calls.append(d) or ["an.example.com", "example.com"]))

    scanner = SubdomainScanner()
    res = _passive_only(scanner, "example.com")
    subs = {e["subdomain"] for e in res["results"]}
    sources = {e["subdomain"]: e["source"] for e in res["results"]}
    assert {"av.example.com", "an.example.com", "example.com"} <= subs
    assert sources["av.example.com"] == "alienvault"
    assert sources["an.example.com"] == "anubis"

    _passive_only(scanner, "example.com")          # second scan hits the cache
    assert av_calls == ["example.com"]
    assert an_calls == ["example.com"]


def test_certspotter_and_urlscan_recorded_and_cached(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh", staticmethod(lambda d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: []))
    cs_calls, us_calls = [], []
    monkeypatch.setattr(SubdomainScanner, "_fetch_certspotter",
                        classmethod(lambda cls, d: cs_calls.append(d) or ["cs.example.com"]))
    monkeypatch.setattr(SubdomainScanner, "_fetch_urlscan",
                        classmethod(lambda cls, d: us_calls.append(d) or ["us.example.com", "example.com"]))

    scanner = SubdomainScanner()
    res = _passive_only(scanner, "example.com")
    sources = {e["subdomain"]: e["source"] for e in res["results"]}
    assert sources.get("cs.example.com") == "certspotter"
    assert sources.get("us.example.com") == "urlscan"

    _passive_only(scanner, "example.com")          # second scan hits the cache
    assert cs_calls == ["example.com"]
    assert us_calls == ["example.com"]


def test_fetch_certspotter_flattens_dns_names(monkeypatch):
    payload = json.dumps([
        {"dns_names": ["a.example.com", "*.b.example.com", "example.com"]},
        {"dns_names": ["c.other.org"]},          # out of domain → filtered
        "junk",                                   # non-dict → skipped
    ]).encode()
    monkeypatch.setattr(ss, "urlopen_retry", lambda req, t, **k: (payload, {}))
    assert SubdomainScanner._fetch_certspotter("example.com") == [
        "a.example.com", "b.example.com", "example.com"]


def test_rapiddns_recorded_and_cached(monkeypatch):
    ss._PASSIVE_CACHE.clear()
    _no_dns(monkeypatch)
    monkeypatch.setattr(SubdomainScanner, "_fetch_crtsh", staticmethod(lambda d: []))
    monkeypatch.setattr(SubdomainScanner, "_fetch_hackertarget",
                        staticmethod(lambda d: []))
    calls = []
    monkeypatch.setattr(SubdomainScanner, "_fetch_rapiddns",
                        classmethod(lambda cls, d: calls.append(d) or ["rd.example.com"]))

    scanner = SubdomainScanner()
    res = _passive_only(scanner, "example.com")
    sources = {e["subdomain"]: e["source"] for e in res["results"]}
    assert sources.get("rd.example.com") == "rapiddns"

    _passive_only(scanner, "example.com")          # cached second scan
    assert calls == ["example.com"]


def test_fetch_rapiddns_extracts_in_domain_hosts_from_html(monkeypatch):
    html = (
        "<table><tr><td>a.example.com</td><td>1.2.3.4</td></tr>"
        "<tr><td>b.sub.example.com</td></tr>"
        "<tr><td>evil.com</td><td>x.other.org</td></tr>"   # out of domain
        "<tr><td>notexample.com</td></tr></table>"          # not a subdomain
    ).encode()
    monkeypatch.setattr(ss, "urlopen_retry", lambda req, t, **k: (html, {}))
    assert SubdomainScanner._fetch_rapiddns("example.com") == [
        "a.example.com", "b.sub.example.com"]


def test_fetch_urlscan_harvests_page_and_task_domains(monkeypatch):
    payload = json.dumps({"results": [
        {"page": {"domain": "a.example.com"}, "task": {"domain": "b.example.com"}},
        {"page": {"domain": "x.other.org"}},     # out of domain → filtered
        {"task": {}},                            # no domain → skipped
        "junk",                                  # non-dict → skipped
    ]}).encode()
    monkeypatch.setattr(ss, "urlopen_retry", lambda req, t, **k: (payload, {}))
    assert SubdomainScanner._fetch_urlscan("example.com") == [
        "a.example.com", "b.example.com"]


def test_extra_source_out_of_domain_names_filtered():
    # The fetch helpers keep only names within the queried domain.
    names = ["a.example.com", "EVIL.com", "x.other.org", "*.b.example.com", "example.com"]
    assert SubdomainScanner._names_in_domain(names, "example.com") == [
        "a.example.com", "b.example.com", "example.com"]


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
