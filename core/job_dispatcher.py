"""Dispatcher for Authorized Worker Orchestration (Roadmap E8, increment 2).

Runs a *claimed* job by handing it to the runner registered for its kind, moving
it running→completed|failed and persisting each transition. The runner map is
**injected**, so the dispatcher is unit-tested offline with fakes; a later step
binds the real runners (collection_runner / audit_runner / mission_runner /
tool_runner / retest_runner) via thin adapters. A single job failure never
raises out of the dispatcher — it is recorded as a ``failed`` job so a dispatch
loop keeps draining the queue.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from core.orchestration import advance_job_status, normalize_job


# A runner: given the pure (running) job dict, do the authorized work and return
# a result reference (e.g. a scan_id / run_id) string.
Runner = Callable[[Dict[str, Any]], Any]


def _pure(job: Any) -> Any:
    """Accept either a pure job dict or a store row (``{payload: {...}}``)."""
    if isinstance(job, dict) and isinstance(job.get("payload"), dict):
        return job["payload"]
    return job


def _persist(store: Any, job: Dict[str, Any], now: str) -> None:
    if store is not None:
        store.save_job(job, now=now or None)


def run_job(job: Any, runners: Dict[str, Runner], *,
            store: Any = None, now: str = "") -> Dict[str, Any]:
    """Execute one claimed job via its kind's runner (persisting each step).

    Returns the terminal job dict. On any failure (no runner, or the runner
    raised) the job is moved to ``failed`` and a transient ``_error`` key carries
    the reason (not persisted). Raises only if ``job`` is not in ``claimed``.
    """
    current = normalize_job(_pure(job))
    if current["status"] != "claimed":
        raise ValueError("only a claimed job can be run")

    running = advance_job_status(current, "running", now=now)
    _persist(store, running, now)

    runner = runners.get(current["kind"]) if isinstance(runners, dict) else None
    if runner is None:
        failed = advance_job_status(running, "failed", now=now)
        _persist(store, failed, now)
        out = dict(failed)
        out["_error"] = f"no runner registered for kind {current['kind']}"
        return out

    try:
        result_ref = runner(running)
    except Exception as exc:  # noqa: BLE001 — a job failure must not kill the loop
        failed = advance_job_status(running, "failed", now=now)
        _persist(store, failed, now)
        out = dict(failed)
        out["_error"] = str(exc)
        return out

    done = advance_job_status(running, "completed", now=now)
    done["result_ref"] = str(result_ref or "")
    _persist(store, done, now)
    return done


def dispatch_next(node: Dict[str, Any], runners: Dict[str, Runner], *,
                  store: Any, now: str = "") -> Optional[Dict[str, Any]]:
    """Claim the next eligible job for ``node`` and run it, or ``None`` if the
    queue has nothing the node may claim."""
    claimed = store.claim_next_job(node, now=now or None)
    if claimed is None:
        return None
    return run_job(claimed, runners, store=store, now=now)
