"""Contract tests for Workbench v2 F2 — ROE/scope templates."""

import pytest

from core.audit_scope import (
    ROE_TEMPLATES,
    apply_roe_template,
    list_roe_templates,
    roe_template,
    validate_roe,
)
from core.audit_workflow import create_audit_run


EXPECTED = {"passive_external", "authenticated_internal", "evidence_only", "release_gate"}


def test_registry_names():
    assert set(ROE_TEMPLATES) == EXPECTED
    names = [tpl["name"] for tpl in list_roe_templates()]
    assert names == sorted(EXPECTED)


def test_roe_template_unknown_raises():
    with pytest.raises(ValueError):
        roe_template("nope")


def test_passive_templates_are_valid_and_passive():
    for name in ("passive_external", "evidence_only", "release_gate"):
        roe = apply_roe_template(name)
        assert roe["profile"] == "client_safe"
        assert roe["passive_only"] is True
        assert roe["active_scan_enabled"] is False
        assert validate_roe(roe)["valid"] is True


def test_authenticated_internal_needs_authorization():
    bare = apply_roe_template("authenticated_internal")
    assert bare["active_scan_enabled"] is True
    assert bare["passive_only"] is False
    # active without allowed_domains is intentionally invalid until the operator fills it
    assert validate_roe(bare)["valid"] is False

    filled = apply_roe_template(
        "authenticated_internal",
        {"allowed_domains": ["app.example.com"], "authorized_by": "client"},
    )
    result = validate_roe(filled)
    assert result["valid"] is True
    assert filled["allowed_domains"] == ["app.example.com"]


def test_overrides_win_over_template():
    roe = apply_roe_template("passive_external", {"denied_domains": ["no.example.com"]})
    assert roe["denied_domains"] == ["no.example.com"]
    assert "label" not in roe and "description" not in roe and "name" not in roe


def test_scenario_template_binds_roe_template_name():
    # light_client_safe -> passive_external ROE, resolved automatically
    run = create_audit_run(
        "example.com", template="light_client_safe", run_id="audit-f2-light"
    )
    assert run["roe"]["passive_only"] is True
    assert run["config"]["roe_template"] == "passive_external"


def test_explicit_roe_overrides_template_binding():
    run = create_audit_run(
        "example.com",
        template="release_regression",
        roe={"allowed_domains": ["example.com"], "passive_only": False,
             "active_scan_enabled": True, "authorized_by": "client"},
        run_id="audit-f2-explicit",
    )
    assert run["roe"]["active_scan_enabled"] is True
