"""core/mission_links.py — Mission Center link integrity (M11), offline."""

import pytest

from core import mission_links, mission_runner, pentest_mission as pm
from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.mission_store import MissionStore


def _ready_mission(project="shop.com"):
    mission = pm.advance_mission_status(
        pm.create_mission(project, "review", allowed_actions=["headers_check"]),
        "ready")
    return MissionStore().save_mission(mission)


def _seed_finding(project="shop.com"):
    return FindingsStore().upsert(project, Finding(
        category="vuln", rule_id="edge", title="Exposed map", severity="high",
        location="https://shop.com/a.js.map").to_store(), scan_id="s1")["finding"]["id"]


def test_link_finding_checked_accepts_existing_rejects_missing():
    mission = pm.create_mission("shop.com", "m", allowed_actions=["headers_check"])
    fid = _seed_finding()
    linked = mission_links.link_finding_checked(mission, fid)
    assert fid in linked["linked_finding_ids"]
    with pytest.raises(ValueError, match="finding not found"):
        mission_links.link_finding_checked(mission, "ghost-finding")


def test_link_audit_run_checked_accepts_existing_rejects_missing():
    saved = _ready_mission()
    _seed_finding()
    out = mission_runner.run_mission(saved["payload"])      # produces a real run
    run_id = out["run_id"]
    mission = pm.create_mission("shop.com", "m2", allowed_actions=["headers_check"])
    linked = mission_links.link_audit_run_checked(mission, run_id)
    assert run_id in linked["linked_audit_run_ids"]
    with pytest.raises(ValueError, match="audit run not found"):
        mission_links.link_audit_run_checked(mission, "ghost-run")


def test_resolve_links_partitions_present_and_stale():
    fid = _seed_finding()
    mission = pm.create_mission("shop.com", "m3", allowed_actions=["headers_check"])
    mission = pm.link_finding(mission, fid)             # present
    mission = pm.link_finding(mission, "deleted-finding")  # stale
    mission = pm.link_audit_run(mission, "deleted-run")    # stale

    out = mission_links.resolve_links(mission)
    assert out["present_findings"] == [fid]
    assert out["stale_findings"] == ["deleted-finding"]
    assert out["stale_runs"] == ["deleted-run"]
    assert out["present_runs"] == []


def test_prune_stale_links_keeps_present_drops_stale():
    fid = _seed_finding()
    mission = pm.create_mission("shop.com", "m5", allowed_actions=["headers_check"])
    mission = pm.link_finding(mission, fid)                 # present
    mission = pm.link_finding(mission, "deleted-finding")   # stale
    mission = pm.link_audit_run(mission, "deleted-run")     # stale

    out = mission_links.prune_stale_links(mission)
    assert out["removed_findings"] == ["deleted-finding"]
    assert out["removed_runs"] == ["deleted-run"]
    assert out["mission"]["linked_finding_ids"] == [fid]
    assert out["mission"]["linked_audit_run_ids"] == []
    # input untouched (pure)
    assert "deleted-finding" in mission["linked_finding_ids"]


def test_prune_stale_links_noop_when_all_present():
    fid = _seed_finding()
    mission = pm.link_finding(
        pm.create_mission("shop.com", "m6", allowed_actions=["headers_check"]), fid)
    out = mission_links.prune_stale_links(mission)
    assert out["removed_runs"] == [] and out["removed_findings"] == []
    assert out["mission"]["linked_finding_ids"] == [fid]


def test_pentest_mission_link_stays_pure():
    # The M1 contract must not gain store access — linking a non-existent id is
    # still accepted by the pure linker (the check lives only in mission_links).
    mission = pm.create_mission("shop.com", "m4", allowed_actions=["headers_check"])
    linked = pm.link_finding(mission, "does-not-exist")
    assert "does-not-exist" in linked["linked_finding_ids"]
