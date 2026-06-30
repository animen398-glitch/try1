"""core/engagement_missions.py — create a mission under an engagement (offline).

Spins up a client-safe mission whose ROE is inherited from the engagement,
persists it, and links it back. Stores isolated per test by conftest.
"""

import pytest

from core import engagement as eng
from core import engagement_missions as em
from core.engagement_store import EngagementStore
from core.mission_store import MissionStore


def _engagement(**kw):
    return eng.create_engagement(
        "Acme", "shop.io",
        scope={"allowed_domains": ["shop.io"]},
        roe={"active_scan_enabled": True, "passive_only": False,
             "rate_limit": "1 rps"},
        authorization={"accepted": True, "authorized_by": "CISO"}, **kw)


def test_create_mission_inherits_roe_and_links():
    out = em.create_mission_under_engagement(
        _engagement(), "External review", allowed_actions=["headers_check"])
    mid = out["mission_id"]
    # mission persisted, on the engagement's project, ROE inherited from scope/roe
    saved = MissionStore().get_mission(mid)
    assert saved is not None and saved["project"] == "shop.io"
    roe = saved["payload"]["roe"]
    assert roe["allowed_domains"] == ["shop.io"]
    assert roe["active_scan_enabled"] is True and roe["passive_only"] is False
    # the orchestrator persists the engagement with the new mission linked
    linked = EngagementStore().get_engagement(out["engagement_id"])["payload"]
    assert mid in linked["linked_mission_ids"]


def test_objective_required():
    with pytest.raises(ValueError, match="objective is required"):
        em.create_mission_under_engagement(_engagement(), "  ")


def test_rejects_non_client_safe_action():
    with pytest.raises(ValueError, match="invalid mission"):
        em.create_mission_under_engagement(_engagement(), "x",
                                           allowed_actions=["exploit"])
