import json

from core.audit_report import (
    audit_summary,
    client_findings,
    render_html,
    render_json,
    render_markdown,
    review_findings,
)
from core.audit_workflow import advance_audit_phase, create_audit_run


def _payload():
    run = create_audit_run("shop.com", phases=["validation"], run_id="audit-report")
    run = advance_audit_phase(
        run,
        "validation",
        {
            "validated_findings": [
                {
                    "finding_id": "f-pass",
                    "title": "Verified critical",
                    "severity": "critical",
                    "validation_status": "verified",
                    "quality_gate": "passed",
                    "client_facing": True,
                    "confidence": 91,
                    "evidence_refs": ["evidence/pass.json"],
                },
                {
                    "finding_id": "f-rejected",
                    "title": "Rejected critical",
                    "severity": "critical",
                    "validation_status": "rejected",
                    "quality_gate": "failed",
                    "client_facing": False,
                    "confidence": 99,
                    "evidence_refs": ["evidence/rejected.json"],
                },
                {
                    "finding_id": "f-review",
                    "title": "Needs review",
                    "severity": "high",
                    "validation_status": "needs_review",
                    "quality_gate": "failed",
                    "client_facing": False,
                    "confidence": 64,
                    "evidence_refs": [],
                },
            ]
        },
    )
    return run


def test_client_findings_excludes_rejected_and_quality_failed():
    payload = _payload()

    assert [f["finding_id"] for f in client_findings(payload)] == ["f-pass"]
    assert {f["finding_id"] for f in review_findings(payload)} == {"f-rejected", "f-review"}


def test_audit_summary_counts_validation_and_quality():
    summary = audit_summary(_payload())

    assert summary["findings"] == 3
    assert summary["client_facing"] == 1
    assert summary["review"] == 2
    assert summary["verified"] == 1
    assert summary["rejected"] == 1
    assert summary["needs_review"] == 1
    assert summary["quality_failed"] == 2


def test_markdown_keeps_rejected_finding_in_appendix_not_client_section():
    text = render_markdown(_payload())

    client_section = text.split("## Client-Facing Findings", 1)[1].split(
        "## Review Appendix", 1
    )[0]
    appendix = text.split("## Review Appendix", 1)[1]
    assert "Verified critical" in client_section
    assert "Rejected critical" not in client_section
    assert "Rejected critical" in appendix


def test_html_is_offline_escaped_and_deterministic():
    run = _payload()
    run["findings"][0]["title"] = "<script>alert(1)</script>"

    first = render_html(run)
    second = render_html(run)

    assert first == second
    assert "<script>alert(1)</script>" not in first
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in first
    assert "https://cdn" not in first.lower()


def test_render_json_is_sorted_and_valid():
    rendered = render_json(_payload())

    assert json.loads(rendered)["run_id"] == "audit-report"
    assert rendered == render_json(_payload())
