"""Contract tests for Workbench v2 F1 — audit scenario templates."""

import pytest

from core.audit_checks import SAFE_CHECKS
from core.audit_schema import validate_audit_payload
from core.audit_templates import (
    AUDIT_TEMPLATES,
    get_template,
    list_templates,
    resolve_template,
)
from core.audit_workflow import AUDIT_PHASES, audit_run_to_json, create_audit_run


EXPECTED_TEMPLATES = {
    "light_client_safe",
    "authenticated_review",
    "evidence_refresh",
    "release_regression",
}


def test_registry_is_internally_consistent():
    assert set(AUDIT_TEMPLATES) == EXPECTED_TEMPLATES
    for name, tpl in AUDIT_TEMPLATES.items():
        assert tpl["phases"], f"{name} must define phases"
        # phases are an ordered subset of the canonical phase list
        for phase in tpl["phases"]:
            assert phase in AUDIT_PHASES, f"{name}: bad phase {phase}"
        order = [AUDIT_PHASES.index(p) for p in tpl["phases"]]
        assert order == sorted(order), f"{name}: phases must keep canonical order"
        for check in tpl["safe_checks"]:
            assert check in SAFE_CHECKS, f"{name}: bad safe check {check}"
        assert isinstance(tpl["min_confidence"], int)
        assert isinstance(tpl["auth_context"], bool)


def test_only_authenticated_review_carries_auth_context():
    assert get_template("authenticated_review")["auth_context"] is True
    for name in EXPECTED_TEMPLATES - {"authenticated_review"}:
        assert get_template(name)["auth_context"] is False


def test_get_template_unknown_raises():
    with pytest.raises(ValueError):
        get_template("does_not_exist")


def test_get_template_returns_isolated_copy():
    tpl = get_template("light_client_safe")
    tpl["phases"].append("independent_verification")
    assert "independent_verification" not in AUDIT_TEMPLATES["light_client_safe"]["phases"]


def test_list_templates_is_sorted_and_named():
    names = [tpl["name"] for tpl in list_templates()]
    assert names == sorted(EXPECTED_TEMPLATES)


def test_resolve_template_phase_override():
    resolved = resolve_template("light_client_safe", phases=["recon_snapshot"])
    assert resolved["phases"] == ["recon_snapshot"]


def test_resolve_template_rejects_bad_phase_override():
    with pytest.raises(ValueError):
        resolve_template("light_client_safe", phases=["totally_invalid"])


def test_bare_create_audit_run_is_v1_identical():
    run = create_audit_run("example.com", run_id="audit-f1-bare")
    for key in ("template", "config", "auth_context", "roe", "baseline_run_id"):
        assert key not in run, f"bare run must not carry v2 key: {key}"
    assert [p["name"] for p in run["phases"]] == list(AUDIT_PHASES)


def test_templated_run_records_config_and_validates():
    run = create_audit_run(
        "example.com",
        template="light_client_safe",
        run_id="audit-f1-light",
    )
    assert run["template"] == "light_client_safe"
    assert run["auth_context"] is False
    assert run["config"]["min_confidence"] == 70
    assert run["config"]["safe_checks"] == [
        "headers_check",
        "cookie_flags_check",
        "source_map_detection",
    ]
    assert [p["name"] for p in run["phases"]] == [
        "recon_snapshot",
        "finding_hunt",
        "validation",
        "structured_output",
    ]
    validate_audit_payload(audit_run_to_json(run), "asa_audit_run")


def test_release_regression_carries_baseline_and_normalized_roe():
    run = create_audit_run(
        "example.com",
        template="release_regression",
        baseline_run_id=" audit-baseline-1 ",
        roe={"allowed_domains": ["example.com"], "authorized_by": "client"},
        run_id="audit-f1-release",
    )
    assert run["baseline_run_id"] == "audit-baseline-1"
    assert run["config"]["compare_to_baseline"] is True
    assert run["roe"]["profile"] == "client_safe"
    assert run["roe"]["allowed_domains"] == ["example.com"]
    validate_audit_payload(audit_run_to_json(run), "asa_audit_run")
