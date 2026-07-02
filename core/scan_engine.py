"""core/scan_engine.py

A tiny, dependency-aware task scheduler for running independent scan phases
concurrently.

The collection pipeline (:mod:`core.collection_runner`) is a set of phases, most
of which are independent network work. This module models them as a DAG — each
task declares the tasks it depends on — and runs independent tasks concurrently
with a bounded worker pool, while dependents wait for their predecessors.

Design notes
------------
* Transport is a plain :class:`~concurrent.futures.ThreadPoolExecutor`. The whole
  codebase is synchronous and thread-based (``SubdomainScanner`` already uses a
  pool, ``utils.rate_limiter`` / ``utils.http_retry`` are blocking, the GUI runs
  the runner inside a QThread), so existing blocking engines schedule with **no
  rewrite**. ``asyncio`` would mean rewriting every network call.
* ``max_concurrency <= 1`` runs the tasks sequentially on the calling thread in a
  deterministic topological order — byte-for-byte the old sequential path, and
  the mode used by tests that need determinism.
* Task functions are zero-arg callables (phase closures capture what they need)
  and return a result. An exception raised by a task is **captured, not
  propagated**: the task's entry in the returned map becomes the exception (or
  the value returned by ``on_error``), and its dependents still run. This mirrors
  the pipeline, where a failed phase records ``status:'Error'`` and the scan
  continues — the *caller* decides what a failed dependency means.
* Cancellation: if ``cancel_event`` is set, no *new* tasks are scheduled;
  in-flight tasks finish and a partial result map is returned. This matches the
  runner's existing phase-boundary cancel semantics.

Pure and side-effect free apart from running the supplied callables; fully
unit-testable without network.
"""

from __future__ import annotations

import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

__all__ = ['Task', 'run_dag']


@dataclass(frozen=True)
class Task:
    """A single node in the scan DAG.

    ``name`` is the node id (unique within a run); ``fn`` is a zero-arg callable
    returning the node's result; ``deps`` names the tasks that must complete
    before this one starts.
    """

    name: str
    fn: Callable[[], Any]
    deps: Tuple[str, ...] = field(default=())


def _index(tasks: List[Task]) -> Dict[str, Task]:
    by_name: Dict[str, Task] = {}
    for t in tasks:
        if t.name in by_name:
            raise ValueError(f'duplicate task name: {t.name!r}')
        by_name[t.name] = t
    for t in tasks:
        for d in t.deps:
            if d not in by_name:
                raise ValueError(
                    f'task {t.name!r} depends on unknown task {d!r}')
    return by_name


def _topo_order(tasks: List[Task]) -> List[str]:
    """Kahn's algorithm, preserving declared order among ready nodes so the
    sequence is deterministic. Raises ``ValueError`` on a cycle."""
    declared = [t.name for t in tasks]
    order_index = {n: i for i, n in enumerate(declared)}
    indeg = {t.name: len(t.deps) for t in tasks}
    dependents: Dict[str, List[str]] = {t.name: [] for t in tasks}
    for t in tasks:
        for d in t.deps:
            dependents[d].append(t.name)

    ready = sorted((n for n in declared if indeg[n] == 0),
                   key=order_index.get)
    order: List[str] = []
    while ready:
        n = ready.pop(0)
        order.append(n)
        for m in dependents[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                ready.append(m)
        ready.sort(key=order_index.get)
    if len(order) != len(tasks):
        raise ValueError('cycle detected in task graph')
    return order


def run_dag(tasks: Iterable[Task], *, max_concurrency: int,
            cancel_event: Optional[threading.Event] = None,
            on_error: Optional[Callable[[str, Exception], Any]] = None,
            ) -> Dict[str, Any]:
    """Run ``tasks`` respecting their dependencies; return ``{name: result}``.

    Independent tasks run concurrently, bounded by ``max_concurrency`` in-flight;
    a dependent starts only once all its ``deps`` have completed. ``max_concurrency
    <= 1`` runs everything sequentially on the calling thread in topological
    order. A task that raises has its exception captured as its result (or the
    value from ``on_error(name, exc)``) and does not stop the run — but a task is
    only scheduled once all of its dependencies have *completed* (a failed
    dependency still unblocks it; a cancelled/unscheduled one does not).
    """
    tasks = list(tasks)
    by_name = _index(tasks)
    order = _topo_order(tasks)          # validates: raises on cycle
    results: Dict[str, Any] = {}
    if not tasks:
        return results

    def _cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    def _run_one(name: str) -> Any:
        try:
            return by_name[name].fn()
        except Exception as e:  # noqa: BLE001 — isolated per task by contract
            if on_error is not None:
                return on_error(name, e)
            return e

    # Sequential fast path — deterministic, no executor, no threads spawned.
    if max_concurrency is None or max_concurrency <= 1:
        for name in order:
            if _cancelled():
                break
            results[name] = _run_one(name)
        return results

    # Concurrent, bounded execution.
    declared = [t.name for t in tasks]
    order_index = {n: i for i, n in enumerate(declared)}
    indeg = {t.name: len(t.deps) for t in tasks}
    dependents: Dict[str, List[str]] = {t.name: [] for t in tasks}
    for t in tasks:
        for d in t.deps:
            dependents[d].append(t.name)

    ready = sorted((n for n in declared if indeg[n] == 0), key=order_index.get)

    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        in_flight: Dict[Any, str] = {}
        while ready or in_flight:
            stopped = _cancelled()
            while not stopped and ready and len(in_flight) < max_concurrency:
                name = ready.pop(0)
                in_flight[pool.submit(_run_one, name)] = name
            if not in_flight:
                break  # nothing running and (cancelled or nothing ready) → done
            done, _ = wait(list(in_flight), return_when=FIRST_COMPLETED)
            for fut in done:
                name = in_flight.pop(fut)
                results[name] = fut.result()  # _run_one never raises
                for m in dependents[name]:
                    indeg[m] -= 1
                    if indeg[m] == 0:
                        ready.append(m)
            ready.sort(key=order_index.get)
    return results
