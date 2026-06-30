"""core/engagement_missions.py
Create a mission under an engagement — the consumer of the scope/ROE inheritance.

``create_mission_under_engagement`` spins up a client-safe mission whose Rules of
Engagement are **seeded from the engagement** (via
:func:`core.engagement.mission_roe_from_engagement`, so the mission inherits the
engagement's scope + ROE), validates it client-safe, persists it to the
``MissionStore``, and links it back to the engagement (existence-checked). It is a
thin store-writing orchestrator over the existing pieces — no new store, no new
contract, and it never runs a tool or opens a socket.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


def create_mission_under_engagement(
    engagement: Dict[str, Any],
    objective: str,
    *,
    allowed_actions: Optional[Iterable[str]] = None,
    mission_store: Optional[Any] = None,
    engagement_store: Optional[Any] = None,
) -> Dict[str, Any]:
    """Create + persist a mission seeded from ``engagement`` and link it back.

    The mission's ROE is inherited from the engagement (scope + ROE folded in by
    ``mission_roe_from_engagement``). The mission is validated client-safe before
    it is saved (a forbidden ``allowed_actions`` entry raises ``ValueError``).
    Returns ``{mission_id, engagement_id}``. Raises ``ValueError`` if the
    engagement has no project or the mission is not client-safe."""
    from core import engagement as eng_mod
    from core import engagement_links, pentest_mission as pm

    normalized = eng_mod.normalize_engagement(engagement)
    if not normalized["project"]:
        raise ValueError("engagement has no project")
    clean_objective = str(objective or "").strip()
    if not clean_objective:
        raise ValueError("objective is required")

    roe = eng_mod.mission_roe_from_engagement(normalized)
    mission = pm.create_mission(normalized["project"], clean_objective, roe=roe,
                               allowed_actions=allowed_actions)
    check = pm.validate_mission(mission)
    if not check["valid"]:
        raise ValueError("invalid mission: " + "; ".join(check["errors"]))

    if mission_store is None:
        from core.mission_store import MissionStore
        mission_store = MissionStore()
    if engagement_store is None:
        from core.engagement_store import EngagementStore
        engagement_store = EngagementStore()

    saved = mission_store.save_mission(mission)
    linked = engagement_links.link_mission_checked(
        normalized, saved["id"], mission_store=mission_store)
    engagement_store.save_engagement(linked)
    return {"mission_id": saved["id"], "engagement_id": normalized["engagement_id"]}
