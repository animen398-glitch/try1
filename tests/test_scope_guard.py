from core.scope_guard import (
    active_phase_decision,
    default_scope_for_target,
    domain_matches,
    host_allowed,
    normalize_scope,
)


def test_normalize_scope_keeps_legacy_missing_scope_compatible():
    scope = normalize_scope(None)

    assert scope["allowed_domains"] == []
    assert scope["denied_domains"] == []
    assert scope["active_scan_enabled"] is True
    assert scope["passive_only"] is False
    assert scope["rate_limit"] is None


def test_default_scope_for_new_project_is_safe_and_target_bound():
    scope = default_scope_for_target("https://Example.com/path")

    assert scope["allowed_domains"] == ["example.com"]
    assert scope["denied_domains"] == []
    assert scope["active_scan_enabled"] is False
    assert scope["passive_only"] is True


def test_domain_matching_supports_exact_and_wildcard():
    assert domain_matches("example.com", "example.com")
    assert domain_matches("api.example.com", "*.example.com")
    assert domain_matches("deep.api.example.com", "*.example.com")
    assert not domain_matches("example.com", "*.example.com")
    assert not domain_matches("evil-example.com", "*.example.com")


def test_denied_domains_win_over_allowed_domains():
    scope = normalize_scope({
        "allowed_domains": ["*.example.com"],
        "denied_domains": ["admin.example.com"],
    })

    assert host_allowed("api.example.com", scope) == (True, "")
    allowed, reason = host_allowed("admin.example.com", scope)
    assert allowed is False
    assert "denied" in reason


def test_active_decision_blocks_passive_only_and_disabled_active():
    passive = active_phase_decision("subdomains", "https://example.com", {
        "passive_only": True,
    })
    disabled = active_phase_decision("nuclei", "https://example.com", {
        "active_scan_enabled": False,
    })

    assert passive.allowed is False
    assert passive.reason == "project is passive_only"
    assert disabled.allowed is False
    assert disabled.reason == "active_scan_enabled is false"


def test_active_decision_blocks_out_of_scope_host():
    decision = active_phase_decision("security", "https://other.com", {
        "allowed_domains": ["example.com", "*.example.com"],
    })

    assert decision.allowed is False
    assert decision.host == "other.com"
    assert "outside allowed domains" in decision.reason
