"""core/retest_run.py — Retest Run core contract (R1).

Pure, deterministic, offline: builds/normalizes/validates a retest-run snapshot
payload and drives its short lifecycle along the legal transitions. No I/O, no
store, no network. Mirrors test_engagement.py / test_pentest_mission.py.
"""

import copy

import pytest

from core import engagement as eng
from core import retest_run as rr


def _engagement():
    return eng.create_engagement("Acme Corp", "shop.io")


def _findings():
    return [
        {"finding_id": "f2", "missing": False, "outcome": "open",
         "title": "XSS", "severity": "high", "status": "OPEN"},
        {"finding_id": "f1", "missing": False, "outcome": "fixed",
         "title": "Header", "severity": "low", "status": "FIXED"},
        {"finding_id": "f3", "missing": True, "outcome": "missing",
         "title": "", "severity": "", "status": ""},
    ]


# ── create / id ────────────────────────────────────────────────────────────────

def test_create_minimal_happy_path():
    run = rr.create_retest_run(_engagement(), created_at="2026-07-01T10:00:00Z")
    assert run["engagement_id"].startswith("eng-")
    assert run["client"] == "Acme Corp"
    assert run["project"] == "shop.io"
    assert run["profile"] == "client_safe"
    assert run["status"] == "pending"
    assert run["created_at"] == "2026-07-01T10:00:00Z"
    assert run["retest_run_id"].startswith("rt-")
    assert run["finding_results"] == []
    assert run["summary"] == {"total": 0, "fixed": 0, "open": 0,
                              "accepted": 0, "missing": 0}


def test_id_deterministic_from_engagement_and_created_at():
    e = _engagement()
    a = rr.create_retest_run(e, created_at="2026-07-01T10:00:00Z")
    b = rr.create_retest_run(e, created_at="2026-07-01T10:00:00Z")
    assert a["retest_run_id"] == b["retest_run_id"]
    # a different created_at → a different run id (each retest is its own record)
    c = rr.create_retest_run(e, created_at="2026-07-02T10:00:00Z")
    assert c["retest_run_id"] != a["retest_run_id"]
    # explicit id wins
    d = rr.create_retest_run(e, created_at="2026-07-01T10:00:00Z",
                             retest_run_id="rt-custom")
    assert d["retest_run_id"] == "rt-custom"


def test_created_at_required():
    with pytest.raises(ValueError, match="created_at is required"):
        rr.create_retest_run(_engagement(), created_at="  ")


def test_engagement_id_required():
    with pytest.raises(ValueError, match="engagement_id is required"):
        rr.create_retest_run({"client": "", "project": ""},
                             created_at="2026-07-01T10:00:00Z")


# ── normalize / summary ─────────────────────────────────────────────────────────

def test_summary_derived_from_results():
    run = rr.create_retest_run(_engagement(), created_at="t",
                               finding_results=_findings())
    assert run["summary"] == {"total": 3, "fixed": 1, "open": 1,
                              "accepted": 0, "missing": 1}


def test_results_deduped_ordering_deterministic():
    run = rr.create_retest_run(_engagement(), created_at="t",
                               finding_results=_findings())
    ids = [r["finding_id"] for r in run["finding_results"]]
    assert ids == sorted(ids)  # sorted by finding_id


def test_normalize_idempotent():
    run = rr.create_retest_run(_engagement(), created_at="t",
                               finding_results=_findings())
    once = rr.normalize_retest_run(run)
    twice = rr.normalize_retest_run(once)
    assert once == twice


def test_normalize_recomputes_summary_even_if_supplied():
    # a tampered/incorrect summary is always overwritten from the results
    run = rr.normalize_retest_run({
        "retest_run_id": "rt-x", "engagement_id": "eng-x", "project": "p",
        "created_at": "t", "finding_results": _findings(),
        "summary": {"total": 999, "fixed": 999, "open": 0,
                    "accepted": 0, "missing": 0},
    })
    assert run["summary"]["total"] == 3
    assert run["summary"]["fixed"] == 1


def test_missing_finding_forces_missing_outcome():
    run = rr.normalize_retest_run({
        "retest_run_id": "rt-x", "engagement_id": "eng-x", "project": "p",
        "created_at": "t",
        "finding_results": [{"finding_id": "f9", "missing": True,
                             "outcome": "fixed"}],
    })
    assert run["finding_results"][0]["outcome"] == "missing"


def test_unknown_outcome_clamped_to_open():
    run = rr.normalize_retest_run({
        "retest_run_id": "rt-x", "engagement_id": "eng-x", "project": "p",
        "created_at": "t",
        "finding_results": [{"finding_id": "f9", "outcome": "banana"}],
    })
    assert run["finding_results"][0]["outcome"] == "open"


def test_normalize_does_not_mutate_input():
    src = {"retest_run_id": "rt-x", "engagement_id": "eng-x", "project": "p",
           "created_at": "t", "finding_results": _findings()}
    before = copy.deepcopy(src)
    rr.normalize_retest_run(src)
    assert src == before


# ── validate ─────────────────────────────────────────────────────────────────────

def test_validate_happy():
    run = rr.create_retest_run(_engagement(), created_at="t",
                               finding_results=_findings())
    check = rr.validate_retest_run(run)
    assert check["valid"] is True
    assert check["errors"] == []


def test_validate_flags_missing_fields():
    check = rr.validate_retest_run({"finding_results": []})
    assert check["valid"] is False
    joined = "; ".join(check["errors"])
    assert "retest_run_id is required" in joined
    assert "engagement_id is required" in joined
    assert "created_at is required" in joined


def test_validate_unknown_status():
    run = rr.create_retest_run(_engagement(), created_at="t")
    run = dict(run, status="weird")
    check = rr.validate_retest_run(run)
    assert check["valid"] is False
    assert any("unknown retest run status" in e for e in check["errors"])


# ── lifecycle ────────────────────────────────────────────────────────────────────

def test_advance_pending_to_completed():
    run = rr.create_retest_run(_engagement(), created_at="t")
    done = rr.advance_retest_run_status(run, "completed")
    assert done["status"] == "completed"
    # input untouched
    assert run["status"] == "pending"


def test_advance_pending_to_failed():
    run = rr.create_retest_run(_engagement(), created_at="t")
    assert rr.advance_retest_run_status(run, "failed")["status"] == "failed"


def test_terminal_states_have_no_exits():
    run = rr.create_retest_run(_engagement(), created_at="t")
    done = rr.advance_retest_run_status(run, "completed")
    with pytest.raises(ValueError, match="illegal retest run transition"):
        rr.advance_retest_run_status(done, "failed")


def test_illegal_transition_rejected():
    run = rr.create_retest_run(_engagement(), created_at="t")
    with pytest.raises(ValueError, match="illegal retest run transition"):
        rr.advance_retest_run_status(run, "pending")


def test_advance_unknown_target_rejected():
    run = rr.create_retest_run(_engagement(), created_at="t")
    with pytest.raises(ValueError, match="unknown retest run status"):
        rr.advance_retest_run_status(run, "banana")


# ── export / schema ──────────────────────────────────────────────────────────────

def test_to_json_schema_valid():
    run = rr.create_retest_run(_engagement(), created_at="t",
                               finding_results=_findings())
    run = rr.advance_retest_run_status(run, "completed")
    payload = rr.retest_run_to_json(run)
    assert payload["status"] == "completed"
    assert payload["summary"]["total"] == 3
    # canonical: re-export is stable
    assert rr.retest_run_to_json(payload) == payload


def test_to_json_rejects_invalid_status():
    run = rr.create_retest_run(_engagement(), created_at="t")
    run = dict(run, status="weird")
    with pytest.raises(ValueError):
        rr.retest_run_to_json(run)


# ── renderers ────────────────────────────────────────────────────────────────────

def test_render_json_is_canonical():
    import json as _json
    run = rr.create_retest_run(_engagement(), created_at="t",
                               finding_results=_findings())
    parsed = _json.loads(rr.render_json(run))
    assert parsed["summary"]["fixed"] == 1
    assert parsed == rr.normalize_retest_run(run)


def test_render_markdown_has_run_metadata_and_table():
    run = rr.create_retest_run(_engagement(), created_at="2026-07-01T10:00:00Z",
                               finding_results=_findings())
    run = rr.advance_retest_run_status(run, "completed")
    md = rr.render_markdown(run)
    assert md.startswith("# Retest Run rt-")
    assert "- Status: completed" in md
    assert "- Taken: 2026-07-01T10:00:00Z" in md
    assert "Fixed: 1" in md
    assert "| Outcome | Severity | Title | Status | Finding |" in md
    assert "XSS" in md            # a finding title reached the table


def test_render_markdown_empty():
    run = rr.create_retest_run(_engagement(), created_at="t")
    md = rr.render_markdown(run)
    assert "No findings linked" in md
