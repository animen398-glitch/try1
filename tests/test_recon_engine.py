"""ReconEngine — report pruning and dynamic-CMS enrichment (offline)."""

import json

from core.recon_engine import ReconEngine, enrich_cms_with_dynamic


class _FakeRegistry:
    def add_record(self, *a, **k):
        pass


def test_recon_report_excludes_large_pwa_manifest(tmp_path):
    """The persisted recon_report.json must drop pwa_manifest (it can be huge),
    while the in-memory result still carries it for the GUI."""
    eng = ReconEngine(data_registry=_FakeRegistry())
    eng.configure(output_dir=str(tmp_path))

    # Stub every network-touching method with canned data.
    eng._resolve_ip = lambda domain: "1.2.3.4"
    eng._geoip = lambda ip: {"country": "US"}
    eng._fetch_with_headers = lambda url: (
        b"<html><head></head><body>wp-content/</body></html>",
        {"Server": "nginx"},
    )
    eng._fetch_pwa_manifest = lambda html, url: {
        "url": url + "/manifest.json",
        "data": {"name": "x" * 5000},
    }

    result = eng.run_recon("https://example.com")

    assert result["status"] == "Success"
    assert result["pwa_manifest"]["data"]["name"]  # present in memory

    report = json.loads((tmp_path / "recon_report.json").read_text(encoding="utf-8"))
    assert "pwa_manifest" not in report          # pruned on disk
    assert report["cms"] == result["cms"]        # rest is intact


def test_recon_populates_technologies_and_infrastructure():
    """run_recon fingerprints tech from headers/scripts and derives the
    Domain → ASN → IP → Provider chain from the GeoIP fields."""
    eng = ReconEngine(data_registry=_FakeRegistry())
    eng._resolve_ip = lambda domain: "1.2.3.4"
    eng._geoip = lambda ip: {"as": "AS13335 Cloudflare, Inc.", "org": "Cloudflare"}
    eng._fetch_with_headers = lambda url: (
        b'<html><head><script src="/gtag/js?id=G-X"></script></head>'
        b'<body></body></html>',
        {"Server": "nginx/1.25.3", "CF-Ray": "abc"},
    )
    eng._fetch_pwa_manifest = lambda html, url: {}

    result = eng.run_recon("https://example.com")

    names = {t["name"]: t for t in result["technologies"]}
    assert names["Nginx"]["version"] == "1.25.3"
    assert "Cloudflare" in names
    assert "Google Analytics" in names

    infra = result["infrastructure"]
    assert infra["asn"] == "AS13335"
    assert infra["provider"] == "Cloudflare"
    assert [hop["role"] for hop in infra["chain"]] == [
        "Domain", "ASN", "IP", "Provider"]


def test_enrich_cms_from_script_url_corpus():
    recon = {"cms": [], "cms_details": {}}
    dynamic = {
        "endpoints": [{"url": "https://cdn.example.com/jquery.min.js"}],
        "json_structures": [],
    }
    enrich_cms_with_dynamic(recon, dynamic)
    assert "jQuery" in recon["cms"]
    assert any("jquery.min.js" in d for d in recon["cms_details"]["jQuery"])


def test_enrich_cms_from_runtime_globals():
    recon = {"cms": [], "cms_details": {}}
    dynamic = {"endpoints": [], "runtime_globals": {"React": True, "Vue.js": False}}
    enrich_cms_with_dynamic(recon, dynamic)
    assert "React" in recon["cms"]
    assert "Vue.js" not in recon["cms"]


def test_enrich_cms_does_not_duplicate_existing():
    recon = {"cms": ["jQuery"], "cms_details": {"jQuery": ["[existing]"]}}
    dynamic = {"endpoints": [{"url": "https://x/jquery.min.js"}],
               "json_structures": []}
    enrich_cms_with_dynamic(recon, dynamic)
    assert recon["cms"].count("jQuery") == 1


def test_enrich_cms_handles_empty_inputs():
    recon = {"cms": [], "cms_details": {}}
    enrich_cms_with_dynamic(recon, {})       # no dynamic data
    assert recon["cms"] == []
    enrich_cms_with_dynamic({}, {})          # both empty — no crash
