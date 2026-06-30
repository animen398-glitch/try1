"""core/engagement.py — Pentest Engagement core contract (F1).

Pure, deterministic, offline: builds/normalizes/validates an engagement payload,
drives its lifecycle along the legal transitions, and links missions / audit runs
/ findings. No I/O, no store, no network. Mirrors test_pentest_mission.py.
"""

import copy

import pytest

from core import engagement as eng


# ── create / id ────────────────────────────────────────────────────────────────

def test_create_minimal_happy_path():
    e = eng.create_engagement("Acme Corp", "shop.io")
    assert e["client"] == "Acme Corp"
    assert e["project"] == "shop.io"
    assert e["profile"] == "client_safe"
    assert e["report_orientation"] == "evidence_first"
    assert e["status"] == "draft"
    assert e["engagement_id"].startswith("eng-")
    # nested shapes present + empty by default
    assert e["scope"] == {"allowed_domains": [], "allowed_ips": [],
                          "forbidden_paths": []}
    assert e["roe"]["passive_only"] is True
    assert e["roe"]["active_scan_enabled"] is False
    assert e["authorization"]["accepted"] is False
    assert e["linked_mission_ids"] == []


def test_deterministic_id():
    a = eng.create_engagement("Acme", "shop.io")
    b = eng.create_engagement("Acme", "shop.io")
    assert a["engagement_id"] == b["engagement_id"]
    # different client/project → different id
    assert eng.create_engagement("Acme", "other.io")["engagement_id"] != a["engagement_id"]
    assert eng.create_engagement("Other", "shop.io")["engagement_id"] != a["engagement_id"]
    # explicit id wins
    assert eng.create_engagement("Acme", "shop.io",
                                 engagement_id="eng-custom")["engagement_id"] == "eng-custom"


def test_required_client_and_project():
    with pytest.raises(ValueError, match="client is required"):
        eng.create_engagement("", "shop.io")
    with pytest.raises(ValueError, match="project is required"):
        eng.create_engagement("Acme", "  ")


# ── normalize ──────────────────────────────────────────────────────────────────

def test_normalize_idempotent():
    e = eng.create_engagement("Acme", "shop.io",
                              scope={"allowed_domains": ["b.io", "a.io", "a.io"]})
    once = eng.normalize_engagement(e)
    twice = eng.normalize_engagement(once)
    assert once == twice


def test_lists_deduped_and_sorted():
    e = eng.normalize_engagement({
        "client": "Acme", "project": "shop.io",
        "scope": {"allowed_domains": ["b.io", "a.io", "a.io", ""],
                  "allowed_ips": ["1.1.1.1", "1.1.1.1"],
                  "forbidden_paths": ["/z", "/a"]},
        "linked_mission_ids": ["m2", "m1", "m1"],
        "linked_audit_run_ids": ["r2", "r1", "r1"],
        "linked_finding_ids": ["f2", "f1", "f1"],
    })
    assert e["scope"]["allowed_domains"] == ["a.io", "b.io"]
    assert e["scope"]["allowed_ips"] == ["1.1.1.1"]
    assert e["scope"]["forbidden_paths"] == ["/a", "/z"]
    assert e["linked_mission_ids"] == ["m1", "m2"]
    assert e["linked_audit_run_ids"] == ["r1", "r2"]
    assert e["linked_finding_ids"] == ["f1", "f2"]


def test_profile_and_orientation_pinned():
    e = eng.normalize_engagement({"client": "Acme", "project": "shop.io",
                                  "profile": "stealth",
                                  "report_orientation": "attacker"})
    assert e["profile"] == "client_safe"
    assert e["report_orientation"] == "evidence_first"


def test_roe_nullable_scalars():
    e = eng.normalize_engagement({"client": "Acme", "project": "shop.io",
                                  "roe": {"rate_limit": "  ", "window": ""}})
    assert e["roe"]["rate_limit"] is None and e["roe"]["window"] is None
    e2 = eng.normalize_engagement({"client": "Acme", "project": "shop.io",
                                   "roe": {"rate_limit": "1 rps",
                                           "window": "09:00-17:00"}})
    assert e2["roe"]["rate_limit"] == "1 rps" and e2["roe"]["window"] == "09:00-17:00"


# ── validate ───────────────────────────────────────────────────────────────────

def test_validate_happy_path():
    e = eng.create_engagement("Acme", "shop.io")
    check = eng.validate_engagement(e)
    assert check["valid"] and check["errors"] == []


def test_validate_requires_client_project():
    check = eng.validate_engagement({"client": "", "project": ""})
    assert not check["valid"]
    assert any("client" in e for e in check["errors"])
    assert any("project" in e for e in check["errors"])


def test_validate_reuses_roe_consistency_rule():
    # active scan with no allowed_domains + passive_only conflict → roe errors
    e = eng.create_engagement("Acme", "shop.io",
                              roe={"active_scan_enabled": True, "passive_only": True})
    check = eng.validate_engagement(e)
    assert not check["valid"]
    assert any(err.startswith("roe:") for err in check["errors"])

    # active scan with allowed_domains + not passive → valid
    ok = eng.create_engagement(
        "Acme", "shop.io",
        scope={"allowed_domains": ["shop.io"]},
        roe={"active_scan_enabled": True, "passive_only": False})
    assert eng.validate_engagement(ok)["valid"]


def test_validate_unknown_status_rejected():
    e = eng.normalize_engagement({"client": "Acme", "project": "shop.io",
                                  "status": "pwned"})
    assert not eng.validate_engagement(e)["valid"]


# ── status transitions ───────────────────────────────────────────────────────--

def _authorizable():
    return eng.create_engagement(
        "Acme", "shop.io",
        authorization={"accepted": True, "authorized_by": "Client CISO"})


def test_legal_transition_draft_to_authorized():
    e = _authorizable()
    out = eng.advance_engagement_status(e, "authorized")
    assert out["status"] == "authorized"


def test_full_lifecycle_path():
    e = eng.link_finding(_authorizable(), "f1")          # so it can later close
    e = eng.advance_engagement_status(e, "authorized")
    e = eng.advance_engagement_status(e, "active")
    e = eng.advance_engagement_status(e, "reporting")
    e = eng.advance_engagement_status(e, "retest")
    e = eng.advance_engagement_status(e, "closed")
    e = eng.advance_engagement_status(e, "archived")
    assert e["status"] == "archived"


def test_illegal_transition_raises():
    e = eng.create_engagement("Acme", "shop.io")          # draft
    with pytest.raises(ValueError, match="illegal engagement transition"):
        eng.advance_engagement_status(e, "active")        # draft cannot jump to active
    with pytest.raises(ValueError, match="unknown engagement status"):
        eng.advance_engagement_status(e, "nope")


def test_authorized_requires_accepted_authorization():
    e = eng.create_engagement("Acme", "shop.io")          # authorization.accepted = False
    with pytest.raises(ValueError, match="authorization must be accepted"):
        eng.advance_engagement_status(e, "authorized")


def test_closed_requires_a_linked_object():
    # reach a state from which 'closed' is legal (reporting), with no links
    e = eng.advance_engagement_status(_authorizable(), "authorized")
    e = eng.advance_engagement_status(e, "active")
    e = eng.advance_engagement_status(e, "reporting")
    with pytest.raises(ValueError, match="cannot be closed"):
        eng.advance_engagement_status(e, "closed")
    # with a linked object → allowed
    e = eng.link_audit_run(e, "run-1")
    assert eng.advance_engagement_status(e, "closed")["status"] == "closed"


def test_archived_is_terminal():
    e = eng.advance_engagement_status(eng.create_engagement("Acme", "shop.io"),
                                      "archived")
    assert e["status"] == "archived"
    with pytest.raises(ValueError, match="illegal engagement transition"):
        eng.advance_engagement_status(e, "draft")


# ── links ────────────────────────────────────────────────────────────────────--

def test_link_helpers_dedupe():
    e = eng.create_engagement("Acme", "shop.io")
    e = eng.link_mission(e, "m1")
    e = eng.link_mission(e, "m1")                          # dup ignored
    e = eng.link_mission(e, "m0")
    e = eng.link_audit_run(e, "r1")
    e = eng.link_finding(e, "f1")
    assert e["linked_mission_ids"] == ["m0", "m1"]
    assert e["linked_audit_run_ids"] == ["r1"]
    assert e["linked_finding_ids"] == ["f1"]


def test_link_helpers_require_id():
    e = eng.create_engagement("Acme", "shop.io")
    for fn in (eng.link_mission, eng.link_audit_run, eng.link_finding):
        with pytest.raises(ValueError):
            fn(e, "  ")


# ── schema export ──────────────────────────────────────────────────────────────

def test_engagement_to_json_is_schema_valid():
    e = eng.create_engagement("Acme", "shop.io",
                              scope={"allowed_domains": ["shop.io"]},
                              authorization={"accepted": True})
    payload = eng.engagement_to_json(e)
    assert payload["engagement_id"].startswith("eng-")
    assert payload["profile"] == "client_safe"
    # canonical: keys sorted
    assert list(payload.keys()) == sorted(payload.keys())


def test_engagement_to_json_rejects_bad_status():
    bad = eng.normalize_engagement({"client": "Acme", "project": "shop.io"})
    bad = copy.deepcopy(bad)
    bad["status"] = "pwned"                                # bypass normalization
    with pytest.raises(ValueError):
        eng.engagement_to_json(bad)


# ── immutability ───────────────────────────────────────────────────────────────

def test_mission_roe_from_engagement_inherits_scope_and_roe():
    e = eng.create_engagement(
        "Acme", "shop.io",
        scope={"allowed_domains": ["shop.io", "x.io"], "allowed_ips": ["1.1.1.1"],
               "forbidden_paths": ["/admin"]},
        roe={"active_scan_enabled": True, "passive_only": False,
             "rate_limit": "2 rps"},
        authorization={"accepted": True, "authorized_by": "CISO"})
    roe = eng.mission_roe_from_engagement(e)
    assert roe["allowed_domains"] == ["shop.io", "x.io"]
    assert roe["forbidden_paths"] == ["/admin"]
    assert roe["active_scan_enabled"] is True and roe["passive_only"] is False
    assert roe["rate_limit"] == "2 rps"
    assert roe["authorized_by"] == "CISO"
    assert roe["profile"] == "client_safe"
    assert "allowed_ips" not in roe          # not part of the mission ROE shape
    # the result is accepted by the mission ROE normalizer
    from core.audit_scope import normalize_roe
    assert normalize_roe(roe)["allowed_domains"] == ["shop.io", "x.io"]


def test_inputs_are_not_mutated():
    e = eng.create_engagement("Acme", "shop.io")
    snapshot = copy.deepcopy(e)
    eng.advance_engagement_status(e, "archived")
    eng.link_mission(e, "m1")
    eng.link_audit_run(e, "r1")
    eng.link_finding(e, "f1")
    eng.normalize_engagement(e)
    eng.engagement_to_json(e)
    assert e == snapshot                                   # original untouched
