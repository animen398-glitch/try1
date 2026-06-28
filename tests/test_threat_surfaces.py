"""Contract tests for KEV/EPSS F5 — report card, web, CSV surfaces."""

import remote.web_app as wa
from core.collection_runner import CollectionRunner
from core.cve_store import CVEStore
from core.report_export import findings_csv


def _seed_threat(cve="CVE-2021-44228"):
    CVEStore().put_cve_threat(cve, {"kev": True, "epss": 0.97, "epss_percentile": 0.99})


def _finding(cve="CVE-2021-44228"):
    return {"id": "f1", "project": "shop.com", "category": "vuln", "rule_id": cve,
            "title": f"{cve} in dep", "severity": "high", "status": "OPEN"}


# ── CSV ───────────────────────────────────────────────────────────────────────

def test_findings_csv_has_kev_epss_columns():
    _seed_threat()
    csv = findings_csv([_finding()])
    header = csv.splitlines()[0]
    assert "KEV" in header and "EPSS" in header
    body = csv.splitlines()[1]
    assert "yes" in body  # KEV listed


def test_findings_csv_blank_threat_when_no_cve():
    import csv as _csv
    import io
    out = findings_csv([{"id": "f2", "category": "header", "title": "x",
                         "severity": "low", "status": "OPEN"}])
    rows = list(_csv.reader(io.StringIO(out)))
    # no CVE → blank KEV cell, row aligns with header, never crashes
    assert len(rows[1]) == len(rows[0])
    assert rows[1][rows[0].index("KEV")] == ""


# ── web read parity ───────────────────────────────────────────────────────────

def test_web_findings_carry_threat_block(monkeypatch):
    from core.findings_store import FindingsStore
    from core.findings_adapter import Finding
    store = FindingsStore()
    dto = Finding(category="vuln", rule_id="CVE-2021-44228",
                  title="CVE-2021-44228 in dep", severity="high").to_store()
    store.upsert("shop.com", dto, scan_id="s1")
    _seed_threat()

    out = wa._findings_list("shop.com")
    threats = [f.get("threat") for f in out["findings"] if f.get("threat")]
    assert threats and threats[0]["kev"] is True
    assert threats[0]["tier"] == "high"


# ── report.html card ──────────────────────────────────────────────────────────

def test_report_html_renders_threat_card():
    report = {"phases": {
        "threat": {"status": "Success", "data": {"summary": {
            "kev": 2, "epss_high": 1, "epss_medium": 3, "enriched": 6}}},
    }}
    html = CollectionRunner()._render_html(report)
    assert "Exploitability (KEV/EPSS)" in html
    assert "KEV: 2" in html
