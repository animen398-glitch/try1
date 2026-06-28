"""Contract tests for KEV/EPSS F2 — orchestrator, annotation, tier mapping."""

import json

from core.cve_store import CVEStore
from core.threat_intel import (
    annotate,
    cve_ids_from_findings,
    enrich_cves,
    kev_events,
    summarize,
    threat_tier_from,
)


def _f(fid, *, rule_id=None, title="", cve=None):
    f = {"id": fid, "category": "vuln", "title": title}
    if rule_id:
        f["rule_id"] = rule_id
    if cve:
        f["cve"] = cve
    return f


# ── tier mapping (the locked thresholds) ──────────────────────────────────────

def test_tier_mapping_boundaries():
    assert threat_tier_from(True, None) == "high"          # KEV wins
    assert threat_tier_from(True, 0.0) == "high"
    assert threat_tier_from(False, 0.90) == "high"
    assert threat_tier_from(False, 0.95) == "high"
    assert threat_tier_from(False, 0.50) == "medium"
    assert threat_tier_from(False, 0.89) == "medium"
    assert threat_tier_from(False, 0.49) is None
    assert threat_tier_from(False, None) is None


# ── CVE extraction from findings ──────────────────────────────────────────────

def test_cve_ids_from_findings_handles_rule_id_and_title():
    findings = [
        _f("a", rule_id="CVE-2021-44228"),
        _f("b", title="nuclei CVE-2014-0160 heartbleed"),
        _f("c", title="no cve here"),
    ]
    assert cve_ids_from_findings(findings) == ["CVE-2014-0160", "CVE-2021-44228"]


# ── enrich (network seam injected) ────────────────────────────────────────────

def _kev(*cves):
    return json.dumps({"vulnerabilities": [{"cveID": c, "dateAdded": "2021-12-10"}
                                           for c in cves]})


def _epss(mapping):
    return json.dumps({"data": [{"cve": c, "epss": str(s), "percentile": str(p)}
                                for c, (s, p) in mapping.items()]})


def test_enrich_cves_persists_and_is_offline_after(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    out = enrich_cves(
        ["CVE-2021-44228", "CVE-2014-0160"],
        store=store,
        kev_get=lambda url: _kev("CVE-2021-44228"),
        epss_get=lambda url: _epss({"CVE-2021-44228": (0.97, 0.99),
                                    "CVE-2014-0160": (0.42, 0.80)}),
    )
    assert out["CVE-2021-44228"]["kev"] is True
    assert out["CVE-2014-0160"]["kev"] is False
    assert out["CVE-2014-0160"]["epss_percentile"] == 0.80
    # second call with NO transport → served from cache (offline), unchanged
    again = enrich_cves(["CVE-2021-44228"], store=store,
                        kev_get=lambda url: "", epss_get=lambda url: "")
    assert again["CVE-2021-44228"]["kev"] is True


def test_enrich_soft_degrades_when_feeds_empty(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    out = enrich_cves(["CVE-2021-44228"], store=store,
                      kev_get=lambda url: "", epss_get=lambda url: "")
    # nothing persisted on a total fetch failure
    assert out == {}
    assert store.get_cve_threat("CVE-2021-44228") is None


# ── annotate (offline derive-on-read) ─────────────────────────────────────────

def test_annotate_attaches_threat_block_and_leaves_others(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    store.put_cve_threat("CVE-2021-44228",
                         {"kev": True, "epss": 0.97, "epss_percentile": 0.99})
    findings = [_f("a", rule_id="CVE-2021-44228"), _f("b", title="no cve")]
    out = annotate(findings, store=store)
    assert out[0]["threat"]["kev"] is True
    assert out[0]["threat"]["tier"] == "high"
    assert "threat" not in out[1]
    # inputs untouched (new dicts returned)
    assert "threat" not in findings[0]


def test_summarize_counts_kev_and_epss(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    store.put_cve_threat("CVE-2021-0001", {"kev": True})
    store.put_cve_threat("CVE-2021-0002", {"kev": False, "epss": 0.6, "epss_percentile": 0.95})
    store.put_cve_threat("CVE-2021-0003", {"kev": False, "epss": 0.3, "epss_percentile": 0.60})
    findings = annotate([_f("a", cve="CVE-2021-0001"), _f("b", cve="CVE-2021-0002"),
                         _f("c", cve="CVE-2021-0003")], store=store)
    s = summarize(findings)
    assert s == {"kev": 1, "epss_high": 1, "epss_medium": 1, "enriched": 3}


# ── kev_events (timeline-shaped KEV rows, derive-on-read) ──────────────────────

def test_kev_events_only_for_kev_annotated_findings(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    store.put_cve_threat("CVE-2021-44228", {"kev": True})
    store.put_cve_threat("CVE-2021-0002", {"kev": False, "epss_percentile": 0.95})
    kev = {**_f("a", rule_id="CVE-2021-44228", title="Log4Shell"),
           "severity": "medium", "first_seen_at": "2026-02-01T00:00:00"}
    epss = {**_f("b", rule_id="CVE-2021-0002", title="High EPSS"),
            "severity": "high", "first_seen_at": "2026-03-01T00:00:00"}
    plain = {**_f("c", title="no cve"), "severity": "high",
             "first_seen_at": "2026-04-01T00:00:00"}
    events = kev_events(annotate([kev, epss, plain], store=store))
    assert len(events) == 1                       # only the KEV one (not EPSS-high)
    ev = events[0]
    assert ev["type"] == "new_kev"
    assert ev["severity"] == "high"               # fixed urgency, base sev in title
    assert ev["section"] == "findings"
    assert ev["scan_id"] is None
    assert ev["at"] == "2026-02-01T00:00:00"      # finding's first_seen_at
    assert "[medium]" in ev["title"] and "KEV" in ev["title"]


def test_kev_events_empty_without_threat_block():
    # Un-annotated findings (cold cache) produce nothing.
    assert kev_events([{"id": "a", "severity": "high", "title": "x"}]) == []
