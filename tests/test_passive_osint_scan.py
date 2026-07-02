"""E1 increment 2 — passive OSINT scan-path integration (offline).

The network is never touched: ``passive_osint.query_internetdb`` is monkeypatched
and the phase / asset wiring is exercised over in-memory report dicts.
"""

import core.passive_osint as po
from core.asset_adapter import derive_assets
from core.collection_runner import CollectionRunner


_RESULT = {
    "ip": "1.1.1.1",
    "ports": [80, 443],
    "hostnames": ["one.one.one.one"],
    "cpes": ["cpe:/a:nginx:nginx"],
    "tags": ["cdn"],
    "vulns": ["CVE-2021-1234"],
    "source": "shodan_internetdb",
}


# --- opt-in gating -----------------------------------------------------------

def test_default_collection_has_passive_osint_off():
    assert CollectionRunner().passive_osint is False


def test_passive_osint_enabled_respects_flag_then_setting(monkeypatch):
    assert CollectionRunner(passive_osint=True)._passive_osint_enabled() is True
    r = CollectionRunner()
    monkeypatch.setattr(
        "core.config.load_settings", lambda: {"passive_osint": {"enabled": True}}
    )
    assert r._passive_osint_enabled() is True
    monkeypatch.setattr(
        "core.config.load_settings", lambda: {"passive_osint": {"enabled": False}}
    )
    assert r._passive_osint_enabled() is False


# --- target IP resolution ----------------------------------------------------

def test_osint_target_ips_extracts_and_dedups():
    report = {"phases": {"recon": {"data": {
        "ip": "1.1.1.1", "infrastructure": {"ip": "1.1.1.1"}}}}}
    assert CollectionRunner._osint_target_ips(report) == ["1.1.1.1"]


def test_osint_target_ips_rejects_non_ip_and_missing():
    non_ip = {"phases": {"recon": {"data": {"ip": "example.com"}}}}
    assert CollectionRunner._osint_target_ips(non_ip) == []
    assert CollectionRunner._osint_target_ips({}) == []


# --- the phase ---------------------------------------------------------------

def test_phase_passive_osint_success(monkeypatch):
    monkeypatch.setattr(po, "query_internetdb",
                        lambda ip, **k: po.parse_internetdb(_RESULT))
    r = CollectionRunner(passive_osint=True)
    out = r._phase_passive_osint({"phases": {"recon": {"data": {"ip": "1.1.1.1"}}}})
    assert out["status"] == "Success"
    assert out["data"]["summary"] == {"ips": 1, "ports": 2, "hostnames": 1, "cves": 1}
    assert out["data"]["results"][0]["ip"] == "1.1.1.1"


def test_phase_passive_osint_skips_without_ip():
    r = CollectionRunner(passive_osint=True)
    out = r._phase_passive_osint({"phases": {"recon": {"data": {}}}})
    assert out["status"] == "Skipped"


def test_phase_passive_osint_skips_when_no_data(monkeypatch):
    monkeypatch.setattr(po, "query_internetdb", lambda ip, **k: {})
    r = CollectionRunner(passive_osint=True)
    out = r._phase_passive_osint({"phases": {"recon": {"data": {"ip": "1.1.1.1"}}}})
    assert out["status"] == "Skipped"


def test_phase_passive_osint_backstops_unexpected_error(monkeypatch):
    # query_internetdb already soft-degrades to {} on a network error (tested in
    # test_passive_osint). Should something *unexpected* raise, the phase's own
    # try/except backstops it to an Error phase — the scan is never sunk.
    def boom(ip, **k):
        raise RuntimeError("net down")

    monkeypatch.setattr(po, "query_internetdb", boom)
    r = CollectionRunner(passive_osint=True)
    out = r._phase_passive_osint({"phases": {"recon": {"data": {"ip": "1.1.1.1"}}}})
    assert out["status"] == "Error"


# --- asset inventory fold ----------------------------------------------------

def test_derive_assets_folds_passive_osint_with_phase_source():
    report = {
        "domain": "example.com",
        "phases": {
            "recon": {"status": "Success", "data": {}},
            "passive_osint": {"status": "Success", "data": {
                "results": [po.parse_internetdb(_RESULT)]}},
        },
    }
    assets = derive_assets(report)
    osint = [a for a in assets if a.attrs.get("source") == "passive_osint"]
    types = {a.type for a in osint}
    assert "ip" in types and "subdomain" in types and "technology" in types
    # correct GONE-gating requires the phase name as the source, not the provider
    assert all(a.attrs["source"] == "passive_osint" for a in osint)


def test_derive_assets_no_passive_phase_is_unchanged():
    report = {"domain": "example.com", "phases": {"recon": {"status": "Success", "data": {}}}}
    assets = derive_assets(report)
    assert not any(a.attrs.get("source") == "passive_osint" for a in assets)


# --- HTML card + coverage ----------------------------------------------------

def test_render_html_passive_osint_card():
    r = CollectionRunner()
    report = {
        "url": "https://x", "domain": "x", "started_at": "", "finished_at": "",
        "project_dir": "",
        "phases": {"passive_osint": {"status": "Success", "data": {
            "summary": {"ips": 1, "ports": 2, "hostnames": 1, "cves": 1}}}},
    }
    html = r._render_html(report)
    assert "Passive OSINT" in html
    assert "zero target traffic" in html
    assert "<script" not in html.lower()


def test_passive_osint_phase_appears_in_coverage():
    from core.coverage import coverage_from_scan_report

    report = {"phases": {
        "recon": {"status": "Success"},
        "passive_osint": {"status": "Skipped", "reason": "no passive OSINT data"},
    }}
    cov = coverage_from_scan_report(report)
    by = {i["phase"]: i for i in cov["items"]}
    assert by["passive_osint"]["status"] == "skipped"
