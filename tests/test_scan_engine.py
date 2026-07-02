"""Tests for core.scan_engine — the dependency-aware task scheduler.

Offline and deterministic: concurrency is proven with a Barrier / peak counter,
never with fragile wall-clock thresholds.
"""

import threading
import time

import pytest

from core.scan_engine import Task, run_dag


def _mk(name, sink):
    """A task fn that records it ran (in order) and returns its name."""
    def _fn():
        sink.append(name)
        return name
    return _fn


def test_empty_graph_returns_empty():
    assert run_dag([], max_concurrency=4) == {}


def test_runs_in_topological_order_sequential():
    order = []
    tasks = [
        Task('c', _mk('c', order), deps=('b',)),
        Task('b', _mk('b', order), deps=('a',)),
        Task('a', _mk('a', order)),
    ]
    results = run_dag(tasks, max_concurrency=1)
    assert order == ['a', 'b', 'c']
    assert results == {'a': 'a', 'b': 'b', 'c': 'c'}


def test_ready_nodes_keep_declared_order_sequential():
    order = []
    # a, b, c all independent — declared order must be preserved deterministically.
    tasks = [Task(n, _mk(n, order)) for n in ('a', 'b', 'c')]
    run_dag(tasks, max_concurrency=1)
    assert order == ['a', 'b', 'c']


def test_independent_tasks_run_concurrently():
    n = 4
    barrier = threading.Barrier(n, timeout=5)
    # barrier.wait() only returns for every task if all n run at once; otherwise
    # it raises BrokenBarrierError, which run_dag would capture as the result.
    tasks = [Task(f't{i}', barrier.wait) for i in range(n)]
    results = run_dag(tasks, max_concurrency=n)
    assert sorted(results.values()) == list(range(n))


def test_max_concurrency_is_bounded():
    lock = threading.Lock()
    state = {'cur': 0, 'peak': 0}

    def work():
        with lock:
            state['cur'] += 1
            state['peak'] = max(state['peak'], state['cur'])
        time.sleep(0.02)
        with lock:
            state['cur'] -= 1

    tasks = [Task(f't{i}', work) for i in range(12)]
    run_dag(tasks, max_concurrency=3)
    assert state['peak'] <= 3
    assert state['cur'] == 0


def test_dependent_runs_after_dependency_concurrent():
    done = []
    seen = {}

    def a():
        time.sleep(0.02)
        done.append('a')
        return 'ra'

    def b():
        seen['a_done_first'] = 'a' in done
        return 'rb'

    tasks = [Task('a', a), Task('b', b, deps=('a',))]
    results = run_dag(tasks, max_concurrency=4)
    assert seen['a_done_first'] is True
    assert results == {'a': 'ra', 'b': 'rb'}


def test_task_error_is_isolated_and_dependents_still_run():
    ran = []

    def boom():
        raise ValueError('kaboom')

    tasks = [
        Task('a', boom),
        Task('b', _mk('b', ran), deps=('a',)),
    ]
    for mc in (1, 4):
        ran.clear()
        results = run_dag(tasks, max_concurrency=mc)
        assert isinstance(results['a'], ValueError)
        assert results['b'] == 'b'
        assert ran == ['b']


def test_on_error_maps_the_result():
    def boom():
        raise RuntimeError('e')

    results = run_dag([Task('a', boom)], max_concurrency=1,
                      on_error=lambda name, exc: {'task': name, 'error': str(exc)})
    assert results['a'] == {'task': 'a', 'error': 'e'}


def test_cancel_before_run_schedules_nothing():
    ev = threading.Event()
    ev.set()
    ran = []
    for mc in (1, 4):
        ran.clear()
        results = run_dag([Task('a', _mk('a', ran))], max_concurrency=mc,
                          cancel_event=ev)
        assert results == {}
        assert ran == []


def test_cancel_midway_stops_new_scheduling():
    ev = threading.Event()
    ran = []

    def a():
        ran.append('a')
        ev.set()      # cancel after the first task
        return 'a'

    tasks = [Task('a', a), Task('b', _mk('b', ran), deps=('a',))]
    results = run_dag(tasks, max_concurrency=2, cancel_event=ev)
    assert results == {'a': 'a'}
    assert ran == ['a']          # 'b' was never scheduled


def test_sequential_and_concurrent_produce_same_results():
    def mk(n):
        return lambda: n * 2

    tasks = [
        Task(f't{i}', mk(i), deps=((f't{i - 1}',) if i % 2 else ()))
        for i in range(6)
    ]
    assert run_dag(tasks, max_concurrency=1) == run_dag(tasks, max_concurrency=4)


def test_cycle_raises():
    tasks = [
        Task('a', lambda: 1, deps=('b',)),
        Task('b', lambda: 1, deps=('a',)),
    ]
    with pytest.raises(ValueError, match='cycle'):
        run_dag(tasks, max_concurrency=1)


def test_unknown_dependency_raises():
    with pytest.raises(ValueError, match='unknown'):
        run_dag([Task('a', lambda: 1, deps=('ghost',))], max_concurrency=4)


def test_duplicate_task_name_raises():
    with pytest.raises(ValueError, match='duplicate'):
        run_dag([Task('a', lambda: 1), Task('a', lambda: 2)], max_concurrency=1)
