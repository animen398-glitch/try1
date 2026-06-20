import pytest

from core.project import ProjectStore
from core.scope_management import clear_scope, patch_scope, set_scope, show_scope


def test_show_scope_reports_new_project_safe_explicit_default(tmp_path):
    store = ProjectStore(tmp_path)

    result = show_scope(store, "https://example.com", create=True)

    assert result["slug"] == "example.com"
    assert result["explicit"] is True
    assert result["scope"]["allowed_domains"] == ["example.com"]
    assert result["scope"]["active_scan_enabled"] is False
    assert result["scope"]["passive_only"] is True


def test_show_scope_missing_project_without_create_raises(tmp_path):
    with pytest.raises(KeyError):
        show_scope(ProjectStore(tmp_path), "missing.com")


def test_patch_scope_normalizes_domains_and_preserves_unspecified_values():
    patched = patch_scope(
        {"active_scan_enabled": False, "passive_only": True},
        allowed_domains=["Example.com", ".example.com"],
        denied_domains=["admin.example.com"],
        rate_limit="2 rps",
    )

    assert patched["allowed_domains"] == ["example.com", "*.example.com"]
    assert patched["denied_domains"] == ["admin.example.com"]
    assert patched["active_scan_enabled"] is False
    assert patched["passive_only"] is True
    assert patched["rate_limit"] == "2 rps"


def test_set_scope_updates_project_metadata(tmp_path):
    store = ProjectStore(tmp_path)

    result = set_scope(
        store,
        "https://example.com",
        allowed_domains=["example.com", "*.example.com"],
        denied_domains=["admin.example.com"],
        active_scan_enabled=True,
        passive_only=False,
        rate_limit="1 rps",
    )

    assert result["scope"]["allowed_domains"] == ["example.com", "*.example.com"]
    assert result["scope"]["denied_domains"] == ["admin.example.com"]
    assert result["scope"]["active_scan_enabled"] is True
    assert result["scope"]["passive_only"] is False
    assert result["scope"]["rate_limit"] == "1 rps"


def test_clear_scope_removes_explicit_scope_and_falls_back_to_legacy(tmp_path):
    store = ProjectStore(tmp_path)
    set_scope(store, "https://example.com", active_scan_enabled=False)

    result = clear_scope(store, "example.com")

    assert result["explicit"] is False
    assert result["scope"]["allowed_domains"] == []
    assert result["scope"]["active_scan_enabled"] is True
