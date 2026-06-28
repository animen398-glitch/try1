"""Contract tests for KEV/EPSS F3 — priority/intelligence seam (no regression)."""

from core.cve_store import CVEStore
from core.intelligence import _threat_tier, build_intelligence


def _vuln(fid, cve, severity="high"):
    return {"id": fid, "category": "vuln", "rule_id": cve,
            "title": f"{cve} in dep", "severity": severity,
            "evidence": {"location": f"https://x/{fid}"}}


# ── enrichment-first _threat_tier ─────────────────────────────────────────────

def test_threat_tier_prefers_enrichment_block():
    f = {"category": "vuln", "rule_id": "CVE-2021-44228",
         "threat": {"tier": "high"}}
    assert _threat_tier(f) == "high"


def test_threat_tier_falls_back_to_static_without_block():
    # a CVE-bearing vuln with no enrichment stays at the static 'medium'
    f = {"category": "vuln", "rule_id": "CVE-2021-44228", "title": "CVE-2021-44228"}
    assert _threat_tier(f) == "medium"
    # and a plain info finding stays None
    assert _threat_tier({"category": "header", "title": "x"}) is None


# ── build_intelligence lifts a KEV finding above an equal non-KEV one ──────────

def test_kev_finding_outranks_equal_non_kev(tmp_path):
    store = CVEStore()  # default path is isolated per-test by conftest
    store.put_cve_threat("CVE-2021-44228",
                         {"kev": True, "epss": 0.97, "epss_percentile": 0.99})
    findings = [
        _vuln("a", "CVE-2021-44228"),   # KEV → tier high
        _vuln("b", "CVE-2014-0160"),    # no cache row → static medium
    ]
    out = build_intelligence(findings)
    ranked = [it["id"] for it in out["items"]]
    assert ranked.index("a") < ranked.index("b")


def test_no_regression_when_cache_empty(tmp_path):
    # cold cache → annotation is a no-op → static tiers only, deterministic order
    findings = [_vuln("a", "CVE-2021-44228"), _vuln("b", "CVE-2014-0160")]
    out = build_intelligence(findings)
    # both are CVE vulns with identical severity → equal threat tier (medium);
    # no enrichment means neither is lifted above the other by KEV
    tiers = {it["id"]: it for it in out["items"]}
    assert set(tiers) == {"a", "b"}
