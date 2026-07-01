"""core/retest_runner.py
Retest Run execution (R3) — take and persist a retest snapshot for an engagement.

Where :func:`core.engagement_retest.build_retest` is the live derive-on-read view
(the non-trivial per-finding status → outcome mapping), this runner freezes one
such view into a persisted :mod:`core.retest_run` snapshot and stores it in the
``RetestRunStore``. It is the retest counterpart of :func:`core.mission_runner.run_mission`
— a thin orchestrator over existing pieces: no second findings source (outcomes
come from ``build_retest`` over the ``FindingsStore``), no network, no tool
execution, no new detection logic.

Lifecycle: a run is created ``pending``, the snapshot is taken, then it advances
``pending → completed`` (persisted) — or ``pending → failed`` if building the
snapshot raises, persisted before the error is re-raised so a run never sticks in
``pending``. The engagement itself is not mutated: the retest ↔ engagement link
lives on the run's ``engagement_id`` (queryable via
``RetestRunStore.list_retest_runs(engagement_id=...)``), so no engagement
contract/schema change is needed.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def run_retest(
    engagement: Dict[str, Any],
    *,
    now: Optional[str] = None,
    findings_store: Optional[Any] = None,
    retest_store: Optional[Any] = None,
    retest_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Take a retest snapshot for ``engagement`` and persist it.

    Reads the current linked-finding outcomes via
    :func:`core.engagement_retest.build_retest`, wraps them into a retest-run
    snapshot (created ``pending``), persists it and advances it to
    ``completed``. On any error while building/creating the snapshot a ``failed``
    run is persisted (best-effort) and the original error re-raised. Returns
    ``{retest_run, retest_run_id, status, summary}``.
    """
    from core import retest_run as rr
    from core.engagement import normalize_engagement
    from core.engagement_retest import build_retest
    from utils.sqlite_store import now_ts

    normalized = normalize_engagement(engagement)
    if not normalized["engagement_id"]:
        raise ValueError("engagement_id is required")

    store = retest_store if retest_store is not None else _default_store()
    stamp = now or now_ts()

    try:
        view = build_retest(normalized, findings_store=findings_store)
        run = rr.create_retest_run(
            normalized, created_at=stamp,
            finding_results=view["findings"], status="pending",
            retest_run_id=retest_run_id)
    except Exception:
        # Persist a failed snapshot (empty results) before surfacing the original
        # error so a run never sticks in 'pending'. A save failure must not mask it.
        try:
            failed = rr.create_retest_run(
                normalized, created_at=stamp, finding_results=[],
                status="pending", retest_run_id=retest_run_id)
            store.save_retest_run(
                rr.advance_retest_run_status(failed, "failed"), now=now)
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to persist retest failure for %s",
                             normalized["engagement_id"])
        raise

    completed = rr.advance_retest_run_status(run, "completed")
    saved = store.save_retest_run(completed, now=now)
    return {
        "retest_run": saved["payload"],
        "retest_run_id": saved["id"],
        "status": "completed",
        "summary": saved["payload"]["summary"],
    }


def _default_store():
    from core.retest_run_store import RetestRunStore
    return RetestRunStore()
