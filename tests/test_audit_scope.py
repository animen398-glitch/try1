from core.audit_scope import normalize_roe, roe_allows_action, roe_summary, validate_roe


def test_normalize_roe_defaults_to_client_safe_passive():
    roe = normalize_roe(None)

    assert roe["profile"] == "client_safe"
    assert roe["passive_only"] is True
    assert roe["active_scan_enabled"] is False


def test_validate_roe_rejects_active_without_allowlist():
    result = validate_roe({"active_scan_enabled": True, "passive_only": False})

    assert result["valid"] is False
    assert "active checks require allowed_domains" in result["errors"]


def test_validate_roe_rejects_active_passive_conflict():
    result = validate_roe({
        "allowed_domains": ["example.com"],
        "active_scan_enabled": True,
        "passive_only": True,
    })

    assert result["valid"] is False
    assert "active_scan_enabled conflicts with passive_only" in result["errors"]


def test_roe_allows_action_only_when_scope_and_profile_allow_it():
    roe = {
        "allowed_domains": ["example.com"],
        "active_scan_enabled": True,
        "passive_only": False,
    }

    assert roe_allows_action("headers_check", "https://example.com", roe)["allowed"] is True
    denied = roe_allows_action("headers_check", "https://evil.com", roe)
    assert denied["allowed"] is False
    assert "outside allowed domains" in denied["reason"]


def test_roe_summary_is_stable_and_readable():
    summary = roe_summary({"allowed_domains": ["Example.com"], "rate_limit": "1 rps"})

    assert "profile=client_safe" in summary
    assert "allowed=example.com" in summary
    assert "rate=1 rps" in summary
