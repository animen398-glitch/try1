"""core/engagement_links.py — Engagement link integrity (F3), offline.

Store-aware checked linking + present/stale resolution over the real Mission /
AuditRun / Findings stores (isolated per test by conftest). The pure
``core.engagement`` contract stays untouched.
"""

import pytest

from core import engagement as eng
from core import engagement_links as el
from core import pentest_mission as pm
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _engagement():
    return eng.create_engagement("Acme", "shop.com")


def _seed_mission(project="shop.com"):
    m = pm.create_mission(project, "review", allowed_actions=["headers_check"])
    return MissionStore().save_mission(m)["id"]


def _seed_finding(project="shop.com"):
    return FindingsStore().upsert(project, Finding(
        category="vuln", rule_id="edge", title="Exposed map", severity="high",
        location="https://shop.com/a.js.map").to_store(), scan_id="s1")["finding"]["id"]


def test_link_mission_checked_accepts_existing_rejects_missing():
    mid = _seed_mission()
    e = el.link_mission_checked(_engagement(), mid)
    assert mid in e["linked_mission_ids"]
    with pytest.raises(ValueError, match="mission not found"):
        el.link_mission_checked(_engagement(), "ghost-mission")


def test_link_finding_checked_accepts_existing_rejects_missing():
    fid = _seed_finding()
    e = el.link_finding_checked(_engagement(), fid)
    assert fid in e["linked_finding_ids"]
    with pytest.raises(ValueError, match="finding not found"):
        el.link_finding_checked(_engagement(), "ghost-finding")


def test_link_audit_run_checked_rejects_missing():
    with pytest.raises(ValueError, match="audit run not found"):
        el.link_audit_run_checked(_engagement(), "ghost-run")


def test_resolve_links_partitions_present_and_stale():
    mid, fid = _seed_mission(), _seed_finding()
    e = _engagement()
    e = eng.link_mission(e, mid)                    # present
    e = eng.link_mission(e, "deleted-mission")      # stale
    e = eng.link_finding(e, fid)                    # present
    e = eng.link_finding(e, "deleted-finding")      # stale
    e = eng.link_audit_run(e, "deleted-run")        # stale

    out = el.resolve_links(e)
    assert out["present_missions"] == [mid]
    assert out["stale_missions"] == ["deleted-mission"]
    assert out["present_findings"] == [fid]
    assert out["stale_findings"] == ["deleted-finding"]
    assert out["stale_runs"] == ["deleted-run"] and out["present_runs"] == []


def test_prune_stale_links_keeps_present_drops_stale():
    mid, fid = _seed_mission(), _seed_finding()
    e = _engagement()
    e = eng.link_mission(e, mid)
    e = eng.link_mission(e, "deleted-mission")
    e = eng.link_finding(e, fid)
    e = eng.link_audit_run(e, "deleted-run")

    out = el.prune_stale_links(e)
    assert out["removed_missions"] == ["deleted-mission"]
    assert out["removed_runs"] == ["deleted-run"]
    assert out["engagement"]["linked_mission_ids"] == [mid]
    assert out["engagement"]["linked_finding_ids"] == [fid]
    assert out["engagement"]["linked_audit_run_ids"] == []
    # input untouched (pure)
    assert "deleted-mission" in e["linked_mission_ids"]


def test_engagement_link_stays_pure():
    # The F1 contract must not gain store access — linking a non-existent id is
    # still accepted by the pure linker (the check lives only in engagement_links).
    e = eng.link_mission(_engagement(), "does-not-exist")
    assert "does-not-exist" in e["linked_mission_ids"]
