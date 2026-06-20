"""Tests for core.tech_risk (EPIC 15 — Technology Risk Scoring).

The engine is pure derive-on-read over a collection report's recon data. It must
flag outdated/EOL technologies and vulnerable JS dependencies as a display posture,
sort by score, summarise, degrade on malformed input, and never raise.
"""

from core.tech_risk import build_technology_risk, load_technology_risk


def _report(technologies=None, dependencies=None):
    return {
        "phases": {
            "recon": {
                "data": {
                    "technologies": technologies if technologies is not None else [],
                    "dependencies": dependencies if dependencies is not None else {},
                }
            }
        }
    }


# ── EOL / outdated technology policies ──────────────────────────────────────────

def test_outdated_php_is_flagged_eol():
    rep = _report(technologies=[
        {"name": "PHP", "version": "7.4.0", "category": "Language",
         "evidence": "header: X-Powered-By"}])
    out = build_technology_risk(rep)
    items = out["items"]
    assert len(items) == 1
    it = items[0]
    assert it["kind"] == "technology" and it["score"] == 35
    assert "EOL" in it["reason"]
    assert out["summary"]["outdated_technologies"] == 1


def test_supported_php_is_version_exposed_not_outdated():
    rep = _report(technologies=[
        {"name": "PHP", "version": "8.2.1", "category": "Language", "evidence": ""}])
    out = build_technology_risk(rep)
    it = out["items"][0]
    assert it["score"] == 10 and "publicly exposed" in it["reason"]
    assert out["summary"]["version_exposed"] == 1
    assert out["summary"]["outdated_technologies"] == 0


def test_version_exposed_server():
    rep = _report(technologies=[
        {"name": "nginx", "version": "1.18.0", "category": "Server", "evidence": ""}])
    out = build_technology_risk(rep)
    it = out["items"][0]
    assert it["kind"] == "technology" and it["score"] == 10
    assert it["band"] == "low"


def test_technology_without_version_is_ignored():
    rep = _report(technologies=[
        {"name": "nginx", "version": "", "category": "Server"},
        {"name": "React", "version": "18.0", "category": "JS Framework"}])
    # No version on the server, and JS Framework is not a version-exposed category.
    assert build_technology_risk(rep)["items"] == []


# ── vulnerable JS dependencies ──────────────────────────────────────────────────

def test_vulnerable_dependency_scored_by_severity():
    rep = _report(dependencies={"libraries": [
        {"name": "jquery", "library": "jquery", "version": "1.7.0",
         "vulnerabilities": [{"cve": "CVE-2020-11022", "severity": "high"},
                             {"cve": "CVE-2019-11358", "severity": "medium"}]}]})
    out = build_technology_risk(rep)
    it = out["items"][0]
    assert it["kind"] == "dependency" and it["score"] == 40 + 25
    assert "worst=high" in it["reason"]
    assert "CVE-2020-11022" in it["evidence"]
    assert out["summary"]["vulnerable_dependencies"] == 1


def test_two_critical_vulns_clamp_and_high_band():
    rep = _report(dependencies={"libraries": [
        {"name": "lodash", "library": "lodash", "version": "4.17.10",
         "vulnerabilities": [{"cve": "CVE-A", "severity": "critical"},
                             {"cve": "CVE-B", "severity": "critical"}]}]})
    it = build_technology_risk(rep)["items"][0]
    assert it["score"] == 100 and it["band"] == "high"


def test_angularjs_dependency_eol_without_cve():
    rep = _report(dependencies={"libraries": [
        {"name": "AngularJS", "library": "angular", "version": "1.5.0",
         "vulnerabilities": []}]})
    it = build_technology_risk(rep)["items"][0]
    assert it["kind"] == "dependency" and it["score"] == 35
    assert "end-of-life" in it["reason"]
    # No CVEs → not counted as a vulnerable dependency.
    assert build_technology_risk(rep)["summary"]["vulnerable_dependencies"] == 0


# ── ranking + summary ───────────────────────────────────────────────────────────

def test_items_sorted_by_score_desc():
    rep = _report(
        technologies=[{"name": "nginx", "version": "1.18.0", "category": "Server"}],
        dependencies={"libraries": [
            {"name": "jquery", "library": "jquery", "version": "1.7.0",
             "vulnerabilities": [{"cve": "CVE-X", "severity": "critical"}]}]})
    items = build_technology_risk(rep)["items"]
    assert [i["score"] for i in items] == sorted(
        [i["score"] for i in items], reverse=True)
    assert items[0]["name"] == "jquery"


def test_summary_counts_and_band():
    rep = _report(
        technologies=[{"name": "PHP", "version": "5.6", "category": "Language"}],
        dependencies={"libraries": [
            {"name": "jquery", "library": "jquery", "version": "1.7.0",
             "vulnerabilities": [{"cve": "CVE-X", "severity": "critical"}]}]})
    s = build_technology_risk(rep)["summary"]
    assert s["items"] == 2
    assert s["vulnerable_dependencies"] == 1
    assert s["outdated_technologies"] == 1
    assert s["score"] == min(100, 35 + 55)
    assert s["band"] in {"high", "medium"}


# ── empty / malformed input (degrade, never raise) ──────────────────────────────

def test_empty_report():
    out = build_technology_risk({})
    assert out == {"summary": {"score": 0, "band": "clean", "items": 0, "high": 0,
                               "medium": 0, "outdated_technologies": 0,
                               "vulnerable_dependencies": 0, "version_exposed": 0},
                   "items": []}


def test_malformed_input_degrades():
    rep = _report(
        technologies=["not-a-dict", None, {"name": "nginx", "version": "1.0",
                                           "category": "Server"}],
        dependencies={"libraries": ["bad", 42,
                                    {"name": "x", "library": "x", "version": "1",
                                     "vulnerabilities": ["nope", None]}]})
    out = build_technology_risk(rep)  # must not raise
    # Only the well-formed server tech survives (the bad lib has no vulns/policy).
    assert any(i["name"] == "nginx" for i in out["items"])


def test_non_dict_report_does_not_raise():
    assert build_technology_risk(None)["items"] == []
    assert build_technology_risk("garbage")["items"] == []


# ── thin reader ─────────────────────────────────────────────────────────────────

class _FakeProject:
    def __init__(self, report, scan_id="s1"):
        self._report = report
        self._scan_id = scan_id

    def latest_scan(self):
        return {"id": self._scan_id} if self._scan_id else {}

    def load_scan_report(self, scan_id):
        return self._report if scan_id == self._scan_id else None


def test_load_technology_risk_reads_latest_scan():
    rep = _report(technologies=[
        {"name": "PHP", "version": "5.6", "category": "Language"}])
    out = load_technology_risk(_FakeProject(rep))
    assert out["summary"]["outdated_technologies"] == 1


def test_load_technology_risk_empty_when_no_scan():
    assert load_technology_risk(_FakeProject({}, scan_id=None)) == {
        "summary": {}, "items": []}
    assert load_technology_risk(None) == {"summary": {}, "items": []}
