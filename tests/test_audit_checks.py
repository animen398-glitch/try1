from core.audit_checks import run_safe_checks


def _roe():
    return {
        "allowed_domains": ["example.com"],
        "active_scan_enabled": True,
        "passive_only": False,
    }


def test_safe_checks_are_scope_gated_before_running():
    out = run_safe_checks(
        "https://evil.com",
        _roe(),
        checks=["headers_check"],
        evidence={"headers_check": {"headers": {}}},
    )

    assert out["findings"] == []
    assert out["results"][0]["allowed"] is False


def test_headers_check_reports_missing_hsts_with_evidence_context():
    out = run_safe_checks(
        "https://example.com",
        _roe(),
        checks=["headers_check"],
        evidence={"headers_check": {"headers": {"server": "nginx"}}},
    )

    finding = out["findings"][0]
    assert finding["rule_id"] == "missing-hsts"
    assert finding["evidence"]["evidence_refs"] == ["headers:https://example.com"]


def test_cookie_flags_check_reports_missing_secure_or_httponly():
    out = run_safe_checks(
        "https://example.com",
        _roe(),
        checks=["cookie_flags_check"],
        evidence={"cookie_flags_check": {"cookies": [{"name": "sid", "secure": False}]}},
    )

    assert out["findings"][0]["category"] == "cookie"
    assert "sid" in out["findings"][0]["title"]


def test_source_map_detection_reports_map_urls_only():
    out = run_safe_checks(
        "https://example.com",
        _roe(),
        checks=["source_map_detection"],
        evidence={"source_map_detection": {"urls": ["https://example.com/app.js", "https://example.com/app.js.map"]}},
    )

    assert len(out["findings"]) == 1
    assert out["findings"][0]["location"].endswith(".map")


def test_endpoint_probe_uses_injected_fetcher_only():
    calls = []

    def fetcher(url):
        calls.append(url)
        return {"status": 200}

    out = run_safe_checks(
        "https://example.com/health",
        _roe(),
        checks=["non_destructive_endpoint_probe"],
        fetcher=fetcher,
    )

    assert calls == ["https://example.com/health"]
    assert out["results"][0]["evidence"]["status"] == 200


def test_unknown_check_is_blocked():
    out = run_safe_checks("https://example.com", _roe(), checks=["exploit_execution"])

    assert out["results"][0]["allowed"] is False
    assert out["results"][0]["reason"] == "unknown safe check"
