"""Contract tests for KEV/EPSS F4 — opt-in collection phase + monitor parity."""

import json

from core.collection_runner import CollectionRunner
from core.cve_store import CVEStore


def _report_with_cve(cve="CVE-2021-44228"):
    return {"phases": {"vulns": {"status": "Success", "findings": [
        {"id": "f1", "category": "vuln", "rule_id": cve, "title": f"{cve} in dep",
         "severity": "high"},
    ]}}}


def _kev(*cves):
    return json.dumps({"vulnerabilities": [{"cveID": c, "dateAdded": "2021-12-10"}
                                           for c in cves]})


def _epss(cve, score, pct):
    return json.dumps({"data": [{"cve": cve, "epss": str(score),
                                 "percentile": str(pct)}]})


def test_phase_off_by_default():
    assert CollectionRunner().threat_feed is False
    r = CollectionRunner()
    r.configure(threat_feed=True)
    assert r.threat_feed is True


def test_phase_warms_cache(monkeypatch):
    import core.threat_feed as tf
    monkeypatch.setattr(tf, "_get_text", lambda url, *a, **k: (
        _kev("CVE-2021-44228") if "known_exploited" in url
        else _epss("CVE-2021-44228", 0.97, 0.99)))

    runner = CollectionRunner(threat_feed=True)
    phase = runner._phase_threat(_report_with_cve())
    assert phase["status"] == "Success"
    assert phase["data"]["summary"]["kev"] == 1
    # cache was warmed → offline annotate now sees KEV
    assert CVEStore().get_cve_threat("CVE-2021-44228")["kev"] is True


def test_phase_no_cves_is_noop():
    report = {"phases": {"vulns": {"status": "Success", "findings": [
        {"id": "f1", "category": "header", "title": "no cve", "severity": "low"}]}}}
    phase = CollectionRunner(threat_feed=True)._phase_threat(report)
    assert phase["status"] == "No CVEs"


def test_phase_soft_degrades_offline(monkeypatch):
    import core.threat_feed as tf
    monkeypatch.setattr(tf, "_get_text", lambda url, *a, **k: "")  # no network
    phase = CollectionRunner(threat_feed=True)._phase_threat(_report_with_cve())
    # CVE present but feeds empty → success with nothing enriched, never raises
    assert phase["status"] == "Success"
    assert phase["data"]["enriched"] == 0
    assert CVEStore().get_cve_threat("CVE-2021-44228") is None


def test_monitor_parity_maps_threat_feed():
    from core import monitor
    # default options keep it off
    assert monitor.default_monitor_options().get("threat_feed") in (None, False)
    # the option flows into the runner kwargs without error
    fn = monitor._build_run_fn("base", {"threat_feed": True})
    assert callable(fn)
