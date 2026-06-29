"""core/mission_runner.py
Mission Center execution (M4) — run an authorized mission as an Audit Run.

A mission is the operator envelope (objective + ROE + client-safe allowed
actions + optional scenario). Running it turns that envelope into a concrete,
evidence-first **Audit Run** using the shared orchestrator (``core.audit_runner``)
— never a second store: the run lands in ``AuditRunStore`` and is linked back to
the mission via the pure ``pentest_mission.link_audit_run`` contract.

Lifecycle: a ``ready`` mission advances ``ready → running`` (persisted), the
audit run is built (safe checks = the mission's allowed actions ∩
``audit_checks.SAFE_CHECKS``; gated by ROE; no network unless a ``fetcher`` is
injected), then the mission advances ``running → completed`` — or ``running →
failed`` if orchestration raises, persisted before the error is re-raised. Pure
guardrails (status machine, ROE/action validation) are reused, never duplicated.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


def _mission_run_id(mission_id: str, now: Optional[str]) -> str:
    """A deterministic-enough run id tying the audit run to its mission."""
    stamp = (now or datetime.now().isoformat(timespec="seconds"))
    safe_stamp = "".join(ch if ch.isalnum() else "-" for ch in stamp)
    return f"mrun-{mission_id}-{safe_stamp}"


def run_mission(
    mission: Dict[str, Any],
    *,
    now: Optional[str] = None,
    run_id: Optional[str] = None,
    evidence: Optional[Dict[str, Dict[str, Any]]] = None,
    fetcher: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Execute a ``ready`` mission as an Audit Run and return the outcome.

    Validates the mission (ROE + client-safe actions) and requires ``ready``
    status, advances it to ``running`` (persisted), builds + saves the audit run
    via :func:`core.audit_runner.build_audit_run`, links the run to the mission
    and advances it to ``completed``. On any orchestration error the mission is
    persisted as ``failed`` and the original error re-raised. Returns
    ``{mission, mission_id, run, rows, run_id, status}``.
    """
    from core import audit_runner
    from core.audit_checks import SAFE_CHECKS
    from core.mission_store import MissionStore
    from core.pentest_mission import (
        advance_mission_status,
        link_audit_run,
        normalize_mission,
        validate_mission,
    )

    normalized = normalize_mission(mission)
    check = validate_mission(normalized)
    if not check["valid"]:
        raise ValueError("mission is not valid: " + "; ".join(check["errors"]))
    if normalized["status"] != "ready":
        raise ValueError(
            f"mission must be 'ready' to run (is '{normalized['status']}')")

    store = MissionStore()
    running = advance_mission_status(normalized, "running")
    store.save_mission(running, now=now)

    project = normalized["project"]
    roe = normalized["roe"]
    template = normalized["template"]
    checks = [action for action in normalized["allowed_actions"]
              if action in SAFE_CHECKS]
    run_id = run_id or _mission_run_id(normalized["mission_id"], now)

    try:
        result = audit_runner.build_audit_run(
            project, run_id=run_id, roe=roe, checks=checks, template=template,
            evidence=evidence, fetcher=fetcher)
    except Exception:
        # Persist the failed state before surfacing the original error so the
        # mission never sticks in 'running'. A save failure must not mask it.
        try:
            store.save_mission(advance_mission_status(running, "failed"), now=now)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to persist mission failure for %s",
                             normalized["mission_id"])
        raise

    linked = link_audit_run(running, result["run"]["run_id"])
    completed = advance_mission_status(linked, "completed")
    saved = store.save_mission(completed, now=now)
    return {
        "mission": saved["payload"],
        "mission_id": normalized["mission_id"],
        "run": result["run"],
        "rows": result["rows"],
        "run_id": result["run"]["run_id"],
        "status": "completed",
    }
