"""core/mission_schedule.py
Mission Center recurring scheduling (M9) — periodic, client-safe re-runs.

Lets an authorized mission re-run on a cadence (daily / weekly / monthly),
reusing the monitor's pure cadence primitives (``compute_next_run`` / ``is_due``)
— never a second scheduler. A scheduled tick **executes the mission's audit run**
(via :mod:`core.audit_runner`, gated by the mission's ROE + allowed actions) and
links it back to the mission, but deliberately does **not** drive the one-shot
mission status machine (``ready → running → completed``): recurring execution
would otherwise fight a lifecycle that has no ``completed → ready`` transition.
The mission's status is left untouched; the schedule (stored separately on the
``MissionStore`` row) tracks ``last_run`` / ``next_run`` / ``last_status``.

State lives on the mission row's ``schedule`` column (set via
``MissionStore.set_schedule``), separate from the canonical payload so the M1
contract stays pure. The tick is standalone (``run_due_missions``) — surfaced by
a GUI button and a web endpoint; an OS-level/cron auto-tick is a later follow-up.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from core.monitor import INTERVALS, compute_next_run, is_due

_RUN_STATUS_OK = "ok"


def _now_dt(now: Optional[Any]) -> datetime:
    if isinstance(now, datetime):
        return now
    if isinstance(now, str) and now:
        try:
            return datetime.fromisoformat(now)
        except ValueError:
            pass
    return datetime.now()


def make_mission_schedule(interval: str, *, enabled: bool = True,
                          now: Optional[Any] = None) -> Dict[str, Any]:
    """A fresh mission schedule dict; the first run is one interval out."""
    if interval not in INTERVALS:
        raise ValueError(f"unknown interval: {interval!r} (use {INTERVALS})")
    base = _now_dt(now)
    return {
        "enabled": bool(enabled),
        "interval": interval,
        "created_at": base.isoformat(timespec="seconds"),
        "last_run": None,
        "last_run_id": None,
        "last_status": None,
        "next_run": compute_next_run(interval, base).isoformat(timespec="seconds"),
    }


def set_mission_schedule(mission_id: str, interval: str, *, enabled: bool = True,
                         store: Optional[Any] = None,
                         now: Optional[Any] = None) -> Dict[str, Any]:
    """Enable a recurring schedule for ``mission_id`` at ``interval``."""
    if store is None:
        from core.mission_store import MissionStore
        store = MissionStore()
    if store.get_mission(mission_id) is None:
        raise KeyError(mission_id)
    schedule = make_mission_schedule(interval, enabled=enabled, now=now)
    store.set_schedule(mission_id, schedule)
    return schedule


def disable_mission_schedule(mission_id: str, *,
                             store: Optional[Any] = None) -> Optional[Dict[str, Any]]:
    """Flip an existing schedule off (kept, not deleted). None if unscheduled."""
    if store is None:
        from core.mission_store import MissionStore
        store = MissionStore()
    schedule = store.get_schedule(mission_id)
    if not isinstance(schedule, dict):
        return None
    updated = dict(schedule)
    updated["enabled"] = False
    store.set_schedule(mission_id, updated)
    return updated


def run_mission_audit(mission_payload: Dict[str, Any], *,
                      now: Optional[Any] = None,
                      run_id: Optional[str] = None) -> Dict[str, Any]:
    """Execute the mission's audit run and link it — **without** touching the
    mission's status (the recurring, status-neutral counterpart of
    :func:`core.mission_runner.run_mission`)."""
    from core import audit_runner
    from core.audit_checks import SAFE_CHECKS
    from core.mission_store import MissionStore
    from core.pentest_mission import link_audit_run, normalize_mission

    mission = normalize_mission(mission_payload)
    checks = [action for action in mission["allowed_actions"]
              if action in SAFE_CHECKS]
    stamp = _now_dt(now).isoformat(timespec="seconds")
    run_id = run_id or _scheduled_run_id(mission["mission_id"], stamp)
    result = audit_runner.build_audit_run(
        mission["project"], run_id=run_id, roe=mission["roe"],
        template=mission["template"], checks=checks)
    linked = link_audit_run(mission, result["run"]["run_id"])
    MissionStore().save_mission(linked, now=stamp)   # status preserved (link only)
    return {"run_id": result["run"]["run_id"], "status": result["run"]["status"]}


def _scheduled_run_id(mission_id: str, stamp: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in stamp)
    return f"msched-{mission_id}-{safe}"


def run_due_missions(*, store: Optional[Any] = None, now: Optional[Any] = None,
                     run: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """Run every enabled + due scheduled mission, advancing its schedule.

    ``run`` (injectable for tests) executes one mission and returns
    ``{run_id, status}``; defaults to :func:`run_mission_audit`. A run failure is
    recorded as the schedule's ``last_status`` and never aborts the sweep.
    Returns one result row per mission that was due.
    """
    if store is None:
        from core.mission_store import MissionStore
        store = MissionStore()
    run = run or run_mission_audit
    now_dt = _now_dt(now)
    now_iso = now_dt.isoformat(timespec="seconds")
    results: List[Dict[str, Any]] = []
    for mission in store.list_scheduled():
        schedule = mission.get("schedule")
        if not isinstance(schedule, dict) or not schedule.get("enabled"):
            continue
        if not is_due(schedule, now_dt):
            continue
        run_id: Optional[str] = None
        try:
            out = run(mission["payload"], now=now_iso)
            run_id = out.get("run_id")
            status = _RUN_STATUS_OK
        except Exception as exc:  # noqa: BLE001 — one bad mission must not abort the sweep
            status = f"error: {exc}"
        updated = dict(schedule)
        updated["last_run"] = now_iso
        updated["last_run_id"] = run_id
        updated["last_status"] = status
        updated["next_run"] = compute_next_run(
            schedule["interval"], now_dt).isoformat(timespec="seconds")
        store.set_schedule(mission["id"], updated)
        results.append({"mission_id": mission["id"], "run_id": run_id,
                        "status": status})
    return results
