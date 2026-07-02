"""Offline tests for the Coverage Gate foundation (Roadmap E2).

No network, no external binaries — optional-capability detection is exercised
through the injectable ``available`` predicate.
"""

import pytest

from core.coverage import (
    COVERAGE_REASONS,
    COVERAGE_STATUSES,
    build_coverage_summary,
    coverage_for_dependency,
    coverage_from_audit_run,
    coverage_item,
    render_coverage_html,
    render_coverage_markdown,
)
from core.audit_report import render_html, render_markdown
from core.audit_workflow import advance_audit_phase, create_audit_run


# --- coverage_item -----------------------------------------------------------

def test_coverage_item_normalizes_and_defaults():
    item = coverage_item("recon", "full")
    assert item == {"phase": "recon", "status": "full", "reason": None, "detail": ""}


def test_coverage_item_rejects_unknown_status():
    with pytest.raises(ValueError):
        coverage_item("recon", "bogus")


def test_coverage_item_rejects_unknown_reason():
    with pytest.raises(ValueError):
        coverage_item("recon", "skipped", "not_a_reason")


def test_coverage_item_requires_phase():
    with pytest.raises(ValueError):
        coverage_item("   ", "full")


def test_vocabulary_is_the_specified_contract():
    assert set(COVERAGE_STATUSES) == {"full", "partial", "skipped", "failed", "unavailable"}
    assert set(COVERAGE_REASONS) == {
        "missing_dependency",
        "scope_denied",
        "roe_denied",
        "failed_phase",
        "skipped_phase",
        "timeout",
        "quota",
        "auth_required",
        "passive_only",
    }


# --- build_coverage_summary --------------------------------------------------

def test_full_coverage_calculation():
    items = [
        coverage_item("recon", "full"),
        coverage_item("subdomains", "full"),
        coverage_item("api", "full"),
    ]
    summary = build_coverage_summary(items)
    assert summary["overall_status"] == "full"
    assert summary["total"] == 3
    assert summary["covered"] == 3
    assert summary["degraded"] == 0
    assert summary["coverage_ratio"] == 1.0
    assert summary["counts"]["full"] == 3


def test_partial_coverage_when_some_full_some_degraded():
    items = [
        coverage_item("recon", "full"),
        coverage_item("dynamic", "unavailable", "missing_dependency"),
    ]
    summary = build_coverage_summary(items)
    assert summary["overall_status"] == "partial"
    assert summary["covered"] == 1
    assert summary["degraded"] == 1
    assert summary["coverage_ratio"] == 0.5
    assert summary["reasons"] == {"missing_dependency": 1}


def test_overall_failed_when_no_full_and_a_failure():
    summary = build_coverage_summary(
        [
            coverage_item("recon", "failed", "failed_phase"),
            coverage_item("api", "skipped", "skipped_phase"),
        ]
    )
    assert summary["overall_status"] == "failed"


def test_overall_skipped_when_no_full_and_only_skips():
    summary = build_coverage_summary([coverage_item("api", "skipped", "skipped_phase")])
    assert summary["overall_status"] == "skipped"


def test_empty_summary_is_unavailable():
    summary = build_coverage_summary([])
    assert summary["overall_status"] == "unavailable"
    assert summary["total"] == 0
    assert summary["coverage_ratio"] == 0.0


def test_summary_coerces_dirty_items_without_raising():
    summary = build_coverage_summary(
        [
            {"phase": "recon", "status": "full"},
            {"name": "legacy", "status": "weird", "reason": "not_real"},
            "not a dict",
            {"no_phase": True},
        ]
    )
    # The clean full item plus the coerced 'legacy' -> unavailable item survive.
    assert summary["total"] == 2
    phases = {i["phase"]: i for i in summary["items"]}
    assert phases["legacy"]["status"] == "unavailable"
    assert phases["legacy"]["reason"] is None  # unknown reason dropped, not raised


# --- coverage_for_dependency (dynamic degradation) ---------------------------

def test_dependency_present_is_full():
    item = coverage_for_dependency("dynamic", "playwright", available=lambda name: True)
    assert item["status"] == "full"
    assert item["reason"] is None


def test_missing_playwright_degrades_to_unavailable():
    item = coverage_for_dependency("dynamic", "playwright", available=lambda name: False)
    assert item["status"] == "unavailable"
    assert item["reason"] == "missing_dependency"
    assert "playwright" in item["detail"]


def test_missing_external_binary_degrades():
    # Simulate an external binary (e.g. nuclei) being absent on this node.
    item = coverage_for_dependency("vuln_templates", "nuclei", available=lambda name: False)
    assert item["status"] == "unavailable"
    assert item["reason"] == "missing_dependency"


def test_dependency_predicate_error_is_treated_as_missing():
    def boom(name):
        raise RuntimeError("detector blew up")

    item = coverage_for_dependency("dynamic", "playwright", available=boom)
    assert item["status"] == "unavailable"


def test_default_detection_reuses_features_and_is_offline():
    # No injected predicate: falls back to core.features (local checks only).
    item = coverage_for_dependency("dynamic", "playwright")
    assert item["status"] in ("full", "unavailable")
    if item["status"] == "unavailable":
        assert item["reason"] == "missing_dependency"


# --- coverage_from_audit_run (legacy edge cases) -----------------------------

def _run_with_phases():
    run = create_audit_run("shop.com", phases=["recon_snapshot", "validation"], run_id="cov-run")
    return advance_audit_phase(run, "recon_snapshot", {})


def test_coverage_derived_from_modern_run_phases():
    run = _run_with_phases()
    summary = coverage_from_audit_run(run)
    phases = {i["phase"]: i for i in summary["items"]}
    assert phases["recon_snapshot"]["status"] == "full"
    # validation never advanced -> still pending -> partial coverage.
    assert phases["validation"]["status"] == "partial"
    assert summary["overall_status"] == "partial"


def test_coverage_maps_failed_and_skipped_phase_statuses():
    run = {
        "run_id": "legacy",
        "phases": [
            {"name": "recon", "status": "failed", "result": {"detail": "network down"}},
            {"name": "api", "status": "skipped", "result": {"reason": "no endpoints"}},
        ],
    }
    summary = coverage_from_audit_run(run)
    phases = {i["phase"]: i for i in summary["items"]}
    assert phases["recon"]["status"] == "failed"
    assert phases["recon"]["reason"] == "failed_phase"
    assert phases["recon"]["detail"] == "network down"
    assert phases["api"]["status"] == "skipped"


def test_legacy_run_without_phases_does_not_crash():
    for legacy in (None, {}, {"phases": "not-a-list"}, {"phases": [None, 42, {}]}, 123, "x"):
        summary = coverage_from_audit_run(legacy)
        assert summary["overall_status"] == "unavailable"
        assert summary["total"] == 0


def test_explicit_coverage_summary_is_reused():
    run = {
        "run_id": "r",
        "coverage": {"items": [{"phase": "recon", "status": "full"}]},
        "phases": [{"name": "ignored", "status": "failed"}],
    }
    summary = coverage_from_audit_run(run)
    # Explicit coverage wins over phase derivation.
    assert [i["phase"] for i in summary["items"]] == ["recon"]
    assert summary["overall_status"] == "full"


def test_explicit_coverage_bare_list_is_accepted():
    run = {"run_id": "r", "coverage": [{"phase": "recon", "status": "full"}], "phases": []}
    summary = coverage_from_audit_run(run)
    assert summary["overall_status"] == "full"


# --- render_coverage_markdown (escaping) -------------------------------------

def test_markdown_has_titled_section_and_ratio():
    summary = build_coverage_summary(
        [coverage_item("recon", "full"), coverage_item("api", "skipped", "skipped_phase")]
    )
    md = render_coverage_markdown(summary)
    assert md.startswith("## Limitations & Coverage")
    assert "Phases covered: 1/2 (50%)" in md
    assert "| Phase | Coverage | Reason | Detail |" in md


def test_markdown_escapes_pipes_and_newlines_in_cells():
    item = coverage_item("weird | phase", "skipped", "skipped_phase", "line1\nline2 | pipe")
    md = render_coverage_markdown(build_coverage_summary([item]))
    # A raw pipe would corrupt the table; it must be escaped, and newlines flattened.
    assert "weird \\| phase" in md
    assert "line1 line2 \\| pipe" in md
    assert "\nline2" not in md.split("Detail")[1]


def test_markdown_accepts_bare_item_list():
    md = render_coverage_markdown([coverage_item("recon", "full")])
    assert "## Limitations & Coverage" in md


def test_markdown_empty_summary_is_graceful():
    md = render_coverage_markdown(build_coverage_summary([]))
    assert "## Limitations & Coverage" in md
    assert "No coverage detail" in md


def test_html_is_escaped():
    item = coverage_item("<script>", "skipped", "skipped_phase", "<b>x</b>")
    out = render_coverage_html(build_coverage_summary([item]))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "&lt;b&gt;x&lt;/b&gt;" in out


# --- audit_report integration ------------------------------------------------

def test_audit_report_markdown_appends_coverage_section():
    run = _run_with_phases()
    text = render_markdown(run)
    assert "## Limitations & Coverage" in text
    # Appears after the review appendix (appended at the end).
    assert text.index("## Review Appendix") < text.index("## Limitations & Coverage")


def test_audit_report_html_appends_coverage_section():
    run = _run_with_phases()
    html_out = render_html(run)
    assert "Limitations &amp; Coverage" in html_out


def test_audit_report_backward_compatible_when_no_coverage_data():
    # A run with only a completed phase still renders a safe fallback section.
    run = create_audit_run("x.com", phases=["validation"], run_id="bc")
    run = advance_audit_phase(run, "validation", {})
    text = render_markdown(run)
    assert "## Limitations & Coverage" in text
    assert "Overall coverage" in text
