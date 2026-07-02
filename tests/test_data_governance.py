"""Offline tests for Sensitive Data Governance (Roadmap E9)."""

from core.data_governance import (
    govern_rows,
    is_sensitive_key,
    redact_data,
    redact_finding,
    redact_text,
)
from core.audit_report import render_html, render_markdown
from core.audit_workflow import advance_audit_phase, create_audit_run


# A representative raw secret (Anthropic key shape) used across cases.
_RAW = "sk-ant-api03ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"


# --- redact_text -------------------------------------------------------------

def test_redact_text_masks_vendor_key_but_keeps_prefix_context():
    out = redact_text(f"the key is {_RAW} embedded")
    assert _RAW not in out
    assert out.startswith("the key is ")
    assert out.endswith(" embedded")
    # mask_value keeps a short prefix + length as context.
    assert "sk-ant" in out


def test_redact_text_masks_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKL"
    out = redact_text(f"token={jwt}")
    assert jwt not in out


def test_redact_text_masks_bearer_token_value_keeps_label():
    tok = "AbCdEf0123456789AbCdEf0123456789"
    out = redact_text(f"Authorization: Bearer {tok}")
    assert tok not in out
    assert "Bearer" in out


def test_redact_text_masks_contextual_assignment_value():
    out = redact_text('api_key = "AKIAIOSFODNN7EXAMPLE1"')
    assert "AKIAIOSFODNN7EXAMPLE1" not in out
    assert "api_key" in out


def test_redact_text_is_idempotent():
    once = redact_text(f"k={_RAW}")
    twice = redact_text(once)
    assert once == twice


def test_redact_text_noop_on_clean_string():
    assert redact_text("Exposed Anthropic API Key") == "Exposed Anthropic API Key"
    assert redact_text("evidence/report.json") == "evidence/report.json"


def test_redact_text_passes_non_strings_through():
    assert redact_text(42) == 42
    assert redact_text(None) is None


# --- sensitive keys ----------------------------------------------------------

def test_is_sensitive_key():
    assert is_sensitive_key("password")
    assert is_sensitive_key("client_secret")
    assert is_sensitive_key("access_token")
    assert is_sensitive_key("api_key")
    assert is_sensitive_key("match")  # raw-secret field from secret_scanner
    assert not is_sensitive_key("author")  # false friend
    assert not is_sensitive_key("severity")
    assert not is_sensitive_key("title")


def test_redact_data_masks_sensitive_key_value_wholesale():
    governed = redact_data({"password": "hunter2secretlong", "severity": "high"})
    assert governed["password"] != "hunter2secretlong"
    assert governed["severity"] == "high"


def test_redact_data_ignores_non_string_sensitive_values():
    # A count named with a marker substring is an int → never masked.
    governed = redact_data({"match_count": 5, "auth_context": True})
    assert governed == {"match_count": 5, "auth_context": True}


def test_redact_data_recurses_and_preserves_structure():
    governed = redact_data(
        {"findings": [{"detail": f"leaked {_RAW}", "confidence": 91}], "n": 2}
    )
    assert _RAW not in governed["findings"][0]["detail"]
    assert governed["findings"][0]["confidence"] == 91
    assert governed["n"] == 2


def test_redact_data_does_not_mutate_input():
    original = {"match": _RAW, "list": [_RAW]}
    governed = redact_data(original)
    assert original["match"] == _RAW  # untouched
    assert original["list"][0] == _RAW
    assert governed["match"] != _RAW


# --- finding-level helpers ---------------------------------------------------

def test_redact_finding_masks_raw_match_field():
    finding = {"type": "Anthropic API Key", "match": _RAW, "severity": "high"}
    governed = redact_finding(finding)
    assert governed["match"] != _RAW
    assert governed["type"] == "Anthropic API Key"


def test_govern_rows_handles_empty_and_non_dict():
    assert govern_rows([]) == []
    assert govern_rows(None) == []


# --- report integration (client-facing boundary) -----------------------------

def _run_with_secret_in_title():
    run = create_audit_run("shop.com", phases=["validation"], run_id="gov")
    return advance_audit_phase(
        run,
        "validation",
        {
            "validated_findings": [
                {
                    "finding_id": "f1",
                    # An upstream slip: a raw secret leaked into a rendered field.
                    "title": f"Exposed key {_RAW}",
                    "severity": "critical",
                    "validation_status": "verified",
                    "quality_gate": "passed",
                    "client_facing": True,
                    "confidence": 90,
                    "evidence_refs": ["evidence/x.json"],
                }
            ]
        },
    )


def test_audit_markdown_report_never_leaks_raw_secret():
    text = render_markdown(_run_with_secret_in_title())
    assert _RAW not in text
    assert "Exposed key" in text  # context preserved


def test_audit_html_report_never_leaks_raw_secret():
    out = render_html(_run_with_secret_in_title())
    assert _RAW not in out


def test_clean_report_output_unchanged_by_governance():
    # A run with no secrets renders exactly as before (governance is a no-op).
    run = create_audit_run("shop.com", phases=["validation"], run_id="clean")
    run = advance_audit_phase(
        run,
        "validation",
        {
            "validated_findings": [
                {
                    "finding_id": "f1",
                    "title": "SQL injection in search",
                    "severity": "high",
                    "validation_status": "verified",
                    "quality_gate": "passed",
                    "client_facing": True,
                    "confidence": 80,
                    "evidence_refs": ["evidence/x.json"],
                }
            ]
        },
    )
    text = render_markdown(run)
    assert "SQL injection in search" in text
