"""Offline tests for Origin Exposure & Cloud Edge Intelligence (Roadmap E6)."""

from core.origin_exposure import build_origin_exposure


def _report(*, edge_cloud="Cloudflare", edge_ip="104.16.0.1", subs=None):
    return {
        "domain": "example.com",
        "phases": {
            "recon": {"status": "Success", "data": {
                "ip": edge_ip,
                "infrastructure": {"cloud": edge_cloud, "ip": edge_ip},
            }},
            "subdomains": {"status": "Success", "data": {"results": subs or []}},
        },
    }


# --- exposure detection ------------------------------------------------------

def test_behind_cdn_with_non_cdn_subdomain_is_exposed():
    report = _report(subs=[
        {"subdomain": "direct.example.com", "ip": "203.0.113.5", "cname": ""},
    ])
    oe = build_origin_exposure(report)
    assert oe["behind_cdn"] is True
    assert oe["exposed"] is True
    assert oe["edge"]["cloud"] == "Cloudflare"
    assert [c["ip"] for c in oe["candidates"]] == ["203.0.113.5"]
    assert oe["candidates"][0]["host"] == "direct.example.com"


def test_not_behind_cdn_is_never_exposed():
    # AWS is a hyperscaler, not a pure CDN edge → no bypass concept.
    report = _report(edge_cloud="AWS", subs=[
        {"subdomain": "direct.example.com", "ip": "203.0.113.5", "cname": ""},
    ])
    oe = build_origin_exposure(report)
    assert oe["behind_cdn"] is False
    assert oe["exposed"] is False


def test_subdomain_on_edge_ip_is_not_a_candidate():
    report = _report(edge_ip="104.16.0.1", subs=[
        {"subdomain": "www.example.com", "ip": "104.16.0.1", "cname": ""},
    ])
    oe = build_origin_exposure(report)
    assert oe["candidates"] == []
    assert oe["exposed"] is False


def test_cdn_fronted_subdomain_is_not_a_candidate():
    # A subdomain whose CNAME points to a CDN resolves to an edge, not an origin.
    report = _report(subs=[
        {"subdomain": "cdn.example.com", "ip": "151.101.1.1",
         "cname": "example.map.fastly.net"},
    ])
    oe = build_origin_exposure(report)
    assert oe["candidates"] == []


def test_candidates_are_deduped_by_ip():
    report = _report(subs=[
        {"subdomain": "a.example.com", "ip": "203.0.113.5", "cname": ""},
        {"subdomain": "b.example.com", "ip": "203.0.113.5", "cname": ""},
        {"subdomain": "c.example.com", "ip": "198.51.100.9", "cname": ""},
    ])
    oe = build_origin_exposure(report)
    assert sorted(c["ip"] for c in oe["candidates"]) == ["198.51.100.9", "203.0.113.5"]


def test_behind_cdn_but_no_candidates_is_not_exposed():
    oe = build_origin_exposure(_report(subs=[]))
    assert oe["behind_cdn"] is True
    assert oe["exposed"] is False
    assert oe["candidates"] == []


def test_edge_cloud_derived_when_infra_cloud_absent():
    # No pre-classified 'cloud'; derive from the provider/ASN name.
    report = {
        "phases": {
            "recon": {"status": "Success", "data": {
                "ip": "104.16.0.1",
                "infrastructure": {"asn_name": "CLOUDFLARENET", "asn": "AS13335"},
            }},
            "subdomains": {"status": "Success", "data": {"results": [
                {"subdomain": "direct.example.com", "ip": "203.0.113.5"},
            ]}},
        }
    }
    oe = build_origin_exposure(report)
    assert oe["behind_cdn"] is True
    assert oe["exposed"] is True


def test_malformed_input_is_safe():
    for bad in (None, {}, {"phases": None}, "x", 5):
        oe = build_origin_exposure(bad)
        assert oe["exposed"] is False
        assert oe["candidates"] == []


def test_no_subdomain_phase_is_not_exposed():
    report = {"phases": {"recon": {"status": "Success", "data": {
        "ip": "104.16.0.1", "infrastructure": {"cloud": "Cloudflare"}}}}}
    oe = build_origin_exposure(report)
    assert oe["behind_cdn"] is True
    assert oe["exposed"] is False


# --- surfaces ----------------------------------------------------------------

def test_collection_runner_attaches_origin_exposure():
    from core.collection_runner import CollectionRunner

    report = _report(subs=[
        {"subdomain": "direct.example.com", "ip": "203.0.113.5", "cname": ""},
    ])
    CollectionRunner()._build_origin_exposure(report)
    assert report["origin_exposure"]["exposed"] is True


def test_report_markdown_surfaces_exposure():
    from core.report_export import report_markdown

    report = _report(subs=[
        {"subdomain": "direct.example.com", "ip": "203.0.113.5", "cname": ""},
    ])
    report["origin_exposure"] = build_origin_exposure(report)
    text = report_markdown(report)
    assert "Origin Exposure" in text
    assert "203.0.113.5" in text
    assert "Cloudflare" in text


def test_report_markdown_omits_section_when_not_exposed():
    from core.report_export import report_markdown

    report = _report(edge_cloud="AWS", subs=[])
    report["origin_exposure"] = build_origin_exposure(report)
    assert "Origin Exposure" not in report_markdown(report)


def test_render_html_origin_exposure_card():
    from core.collection_runner import CollectionRunner

    r = CollectionRunner()
    report = _report(subs=[
        {"subdomain": "direct.example.com", "ip": "203.0.113.5", "cname": ""},
    ])
    report["url"] = "https://example.com"
    report["started_at"] = report["finished_at"] = report["project_dir"] = ""
    report["origin_exposure"] = build_origin_exposure(report)
    html = r._render_html(report)
    assert "Origin Exposure" in html
    assert "203.0.113.5" in html
    assert "<script" not in html.lower()
