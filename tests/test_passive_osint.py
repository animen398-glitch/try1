"""Offline tests for the Passive OSINT Intelligence Layer (Roadmap E1).

Fully offline: the transport is injected, so no network is ever touched.
"""

import pytest

from core.passive_osint import (
    PASSIVE_SOURCES,
    _fetch,
    list_sources,
    osint_to_assets,
    osint_to_findings,
    parse_censys_host,
    parse_internetdb,
    parse_shodan_host,
    query_best,
    query_censys,
    query_internetdb,
    query_shodan,
)


_SAMPLE = {
    "ip": "1.1.1.1",
    "ports": [80, 443, 443, "22", "bad"],
    "hostnames": ["one.one.one.one", "one.one.one.one", " "],
    "cpes": ["cpe:/a:nginx:nginx"],
    "tags": ["cdn"],
    "vulns": ["CVE-2021-1234", "CVE-2020-5678"],
}


# --- registry ----------------------------------------------------------------

def test_registry_has_keyless_internetdb():
    src = PASSIVE_SOURCES["shodan_internetdb"]
    assert src.requires_key is False
    assert src.target_kind == "ip"


def test_list_sources_keyless_filter():
    assert all(not s.requires_key for s in list_sources(keyless_only=True))
    assert any(s.name == "shodan_internetdb" for s in list_sources())


# --- parse -------------------------------------------------------------------

def test_parse_normalizes_ports_and_dedups():
    parsed = parse_internetdb(_SAMPLE)
    assert parsed["ip"] == "1.1.1.1"
    assert parsed["ports"] == [22, 80, 443]  # ints, deduped, sorted, 'bad' dropped
    assert parsed["hostnames"] == ["one.one.one.one"]  # deduped, blank dropped
    assert parsed["cpes"] == ["cpe:/a:nginx:nginx"]
    assert parsed["vulns"] == ["CVE-2021-1234", "CVE-2020-5678"]
    assert parsed["source"] == "shodan_internetdb"


def test_parse_missing_ip_is_empty():
    assert parse_internetdb({"ports": [80]}) == {}
    assert parse_internetdb(None) == {}
    assert parse_internetdb("nope") == {}


def test_parse_tolerates_missing_keys():
    parsed = parse_internetdb({"ip": "8.8.8.8"})
    assert parsed["ip"] == "8.8.8.8"
    assert parsed["ports"] == []
    assert parsed["hostnames"] == []
    assert parsed["vulns"] == []


# --- query (injected transport) ----------------------------------------------

def test_query_uses_injected_fetch_and_parses():
    calls = {}

    def fake_fetch(url, timeout):
        calls["url"] = url
        return _SAMPLE

    result = query_internetdb("1.1.1.1", fetch=fake_fetch)
    assert result["ip"] == "1.1.1.1"
    assert calls["url"] == "https://internetdb.shodan.io/1.1.1.1"


def test_query_rejects_non_ip_without_fetching():
    calls = {"n": 0}

    def fake_fetch(url, timeout):
        calls["n"] += 1
        return _SAMPLE

    assert query_internetdb("example.com", fetch=fake_fetch) == {}
    assert query_internetdb("", fetch=fake_fetch) == {}
    assert calls["n"] == 0  # no lookup attempted for a non-IP


def test_query_soft_degrades_on_fetch_error():
    def boom(url, timeout):
        raise RuntimeError("network down")

    assert query_internetdb("1.1.1.1", fetch=boom) == {}


def test_query_accepts_ipv6():
    result = query_internetdb("2606:4700:4700::1111", fetch=lambda u, t: {"ip": "x"})
    # Valid v6 address → a lookup is attempted (parse then handles the payload).
    assert isinstance(result, dict)


def test_fetch_rejects_non_https():
    with pytest.raises(ValueError):
        _fetch("http://internetdb.shodan.io/1.1.1.1", 5.0)


# --- mapping into canonical DTOs ---------------------------------------------

def test_osint_to_assets_maps_ip_hosts_and_cpes():
    assets = osint_to_assets(parse_internetdb(_SAMPLE))
    by_type = {}
    for a in assets:
        by_type.setdefault(a.type, []).append(a)
    assert len(by_type["ip"]) == 1
    ip_asset = by_type["ip"][0]
    assert ip_asset.attrs["source"] == "shodan_internetdb"
    assert ip_asset.attrs["ports"] == [22, 80, 443]
    assert by_type["subdomain"][0].value == "one.one.one.one"
    assert by_type["technology"][0].attrs["source"] == "shodan_internetdb"


def test_osint_to_assets_empty_on_no_ip():
    assert osint_to_assets({}) == []
    assert osint_to_assets(None) == []


def test_osint_to_findings_uses_canonical_cve_identity():
    findings = osint_to_findings(parse_internetdb(_SAMPLE))
    assert len(findings) == 2
    f = findings[0]
    assert f.category == "vuln"
    assert f.rule_id in ("cve-2021-1234", "cve-2020-5678")
    assert f.severity == "Info"  # passive/unverified, never client-critical
    assert f.source == "shodan_internetdb"


def test_osint_to_findings_empty_when_no_vulns():
    assert osint_to_findings(parse_internetdb({"ip": "8.8.8.8"})) == []


# --- keyed providers (E1-3) --------------------------------------------------

_SHODAN_HOST = {
    "ip_str": "1.1.1.1",
    "ports": [80, 443],
    "hostnames": ["one.one.one.one"],
    "tags": ["cdn"],
    "vulns": ["CVE-2021-0001"],
    "data": [
        {"cpe23": ["cpe:/a:nginx:nginx"], "vulns": {"CVE-2020-9999": {}}},
    ],
}

_CENSYS_HOST = {
    "result": {
        "ip": "1.1.1.1",
        "services": [
            {"port": 443, "software": [
                {"uniform_resource_identifier": "cpe:2.3:a:nginx:nginx"}]},
            {"port": 80},
        ],
        "dns": {"names": ["one.one.one.one"]},
        "labels": ["cdn"],
    }
}


def test_registry_has_keyed_providers():
    assert PASSIVE_SOURCES["shodan_api"].requires_key is True
    assert PASSIVE_SOURCES["censys"].requires_key is True
    # keyless filter now excludes them
    keyless = {s.name for s in list_sources(keyless_only=True)}
    assert "shodan_api" not in keyless and "shodan_internetdb" in keyless


def test_parse_shodan_host_flattens_cpes_and_vulns():
    parsed = parse_shodan_host(_SHODAN_HOST)
    assert parsed["ip"] == "1.1.1.1"
    assert parsed["ports"] == [80, 443]
    assert parsed["cpes"] == ["cpe:/a:nginx:nginx"]
    assert set(parsed["vulns"]) == {"CVE-2021-0001", "CVE-2020-9999"}
    assert parsed["source"] == "shodan_api"


def test_query_shodan_requires_key_and_uses_fetch():
    calls = {}
    assert query_shodan("1.1.1.1", "", fetch=lambda u, t: _SHODAN_HOST) == {}

    def fake(url, timeout):
        calls["url"] = url
        return _SHODAN_HOST

    out = query_shodan("1.1.1.1", "KEY", fetch=fake)
    assert out["source"] == "shodan_api"
    assert "key=KEY" in calls["url"] and "api.shodan.io" in calls["url"]


def test_query_shodan_soft_degrades():
    def boom(u, t):
        raise RuntimeError("down")

    assert query_shodan("1.1.1.1", "KEY", fetch=boom) == {}
    assert query_shodan("not-ip", "KEY", fetch=lambda u, t: _SHODAN_HOST) == {}


def test_parse_and_query_censys():
    parsed = parse_censys_host(_CENSYS_HOST)
    assert parsed["ports"] == [80, 443]
    assert parsed["hostnames"] == ["one.one.one.one"]
    assert parsed["cpes"] == ["cpe:2.3:a:nginx:nginx"]
    assert parsed["source"] == "censys"

    assert query_censys("1.1.1.1", "", "", fetch=lambda u, t: _CENSYS_HOST) == {}
    out = query_censys("1.1.1.1", "id", "sec", fetch=lambda u, t: _CENSYS_HOST)
    assert out["ip"] == "1.1.1.1"


def test_query_best_prefers_shodan_when_keyed():
    fetch_map = {
        "shodan_api": lambda u, t: _SHODAN_HOST,
        "shodan_internetdb": lambda u, t: {"ip": "1.1.1.1", "ports": [22]},
    }
    out = query_best("1.1.1.1", config={"shodan_api_key": "KEY"}, fetch_map=fetch_map)
    assert out["source"] == "shodan_api"


def test_query_best_falls_back_to_internetdb_without_keys():
    fetch_map = {"shodan_internetdb": lambda u, t: {"ip": "1.1.1.1", "ports": [22]}}
    out = query_best("1.1.1.1", config={}, fetch_map=fetch_map)
    assert out["source"] == "shodan_internetdb"
    assert out["ports"] == [22]


def test_query_best_censys_when_only_censys_keyed():
    fetch_map = {
        "censys": lambda u, t: _CENSYS_HOST,
        "shodan_internetdb": lambda u, t: {},
    }
    out = query_best("1.1.1.1",
                     config={"censys_api_id": "id", "censys_api_secret": "sec"},
                     fetch_map=fetch_map)
    assert out["source"] == "censys"
