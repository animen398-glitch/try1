"""Contract tests for KEV/EPSS F1 — feed parsers, fetchers, and CVE cache."""

import json

from core.cve_store import CVEStore
from core.threat_feed import (
    fetch_epss,
    fetch_epss_csv,
    fetch_kev,
    parse_epss,
    parse_epss_csv,
    parse_kev,
)


EPSS_CSV_SAMPLE = (
    "#model_version:v2024.01.01,score_date:2024-01-01T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97500,0.99000\n"
    "cve-2014-0160,0.42000,0.80000\n"
)


KEV_SAMPLE = json.dumps({
    "title": "CISA KEV",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
        {"cveID": "cve-2014-0160", "dateAdded": "2022-05-04"},
        {"notACve": True},
    ],
})

EPSS_SAMPLE = json.dumps({
    "status": "OK",
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97500", "percentile": "0.99000"},
        {"cve": "CVE-2014-0160", "epss": "0.42000", "percentile": "0.80000"},
    ],
})


# ── pure parsers ──────────────────────────────────────────────────────────────

def test_parse_kev_normalizes_and_skips_bad_rows():
    out = parse_kev(KEV_SAMPLE)
    assert out == {"CVE-2021-44228": "2021-12-10", "CVE-2014-0160": "2022-05-04"}


def test_parse_epss_coerces_floats_and_clamps():
    out = parse_epss(EPSS_SAMPLE)
    assert out["CVE-2021-44228"]["score"] == 0.975
    assert out["CVE-2021-44228"]["percentile"] == 0.99


def test_parsers_degrade_on_malformed_or_empty():
    for bad in ("", "not json", "[]", json.dumps({"x": 1})):
        assert parse_kev(bad) == {}
        assert parse_epss(bad) == {}


def test_parse_epss_csv_skips_comments_and_normalizes():
    out = parse_epss_csv(EPSS_CSV_SAMPLE)
    assert set(out) == {"CVE-2021-44228", "CVE-2014-0160"}     # cve upper-cased
    assert out["CVE-2021-44228"] == {"score": 0.975, "percentile": 0.99}
    assert out["CVE-2014-0160"]["score"] == 0.42


def test_parse_epss_csv_degrades_on_empty_or_comments_only():
    assert parse_epss_csv("") == {}
    assert parse_epss_csv("#only a comment line\n") == {}


# ── fetchers with injected transport (no network) ─────────────────────────────

def test_fetch_kev_uses_injected_get():
    out = fetch_kev(get=lambda url: KEV_SAMPLE)
    assert "CVE-2021-44228" in out


def test_fetch_kev_soft_degrades_when_transport_empty():
    assert fetch_kev(get=lambda url: "") == {}


def test_fetch_epss_batches_and_dedupes():
    seen = []

    def fake_get(url):
        seen.append(url)
        return EPSS_SAMPLE

    out = fetch_epss(["CVE-2021-44228", "CVE-2014-0160", "CVE-2021-44228"],
                     get=fake_get, batch=1)
    # 2 unique CVEs, batch=1 → two requests; result merged
    assert len(seen) == 2
    assert set(out) == {"CVE-2021-44228", "CVE-2014-0160"}


def test_fetch_epss_csv_one_download_for_all_cves():
    seen = []

    def fake_get(url):
        seen.append(url)
        return EPSS_CSV_SAMPLE

    out = fetch_epss_csv(get=fake_get)
    assert len(seen) == 1                       # the whole dataset in one request
    assert set(out) == {"CVE-2021-44228", "CVE-2014-0160"}


def test_fetch_epss_csv_soft_degrades_when_transport_empty():
    assert fetch_epss_csv(get=lambda url: "") == {}


# ── CVEStore threat cache ─────────────────────────────────────────────────────

def test_cve_store_put_get_threat(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    store.put_cve_threat("CVE-2021-44228",
                         {"kev": True, "kev_date": "2021-12-10",
                          "epss": 0.975, "epss_percentile": 0.99})
    row = store.get_cve_threat("CVE-2021-44228")
    assert row["kev"] is True
    assert row["epss"] == 0.975 and row["epss_percentile"] == 0.99
    assert "age" in row
    assert store.get_cve_threat("CVE-0000-0000") is None


def test_cve_store_threat_in_stats_clear_prune(tmp_path):
    store = CVEStore(tmp_path / "cve.db")
    store.put_cve_threat("CVE-1", {"kev": False, "epss": 0.1, "epss_percentile": 0.2})
    assert store.stats()["cve_threat"] == 1
    # prune with cap 0 drops everything; threat table is bounded too
    store.prune(max_age_days=3650, max_rows=0)
    assert store.stats()["cve_threat"] == 0
    store.put_cve_threat("CVE-2", {"kev": True})
    assert store.clear() >= 1
    assert store.get_cve_threat("CVE-2") is None
