"""T7: the LAN console's in-memory state stays bounded so a long-running server
process can't grow without limit. Offline, no network."""
import asyncio

import pytest

pytest.importorskip('fastapi')
import remote.web_app as web  # noqa: E402


def test_job_results_evict_oldest(monkeypatch):
    monkeypatch.setattr(web, '_job_results', {})
    monkeypatch.setattr(web, '_MAX_JOB_RESULTS', 3)

    for i in range(5):
        web._record_job_result(f'j{i}', {'n': i})

    assert len(web._job_results) == 3
    assert 'j0' not in web._job_results and 'j1' not in web._job_results
    assert 'j4' in web._job_results and web._job_results['j4'] == {'n': 4}


def test_push_bounds_log_queue(monkeypatch):
    """With no SSE consumer draining, _push drops the oldest so the queue stays
    capped and the newest messages are retained."""
    monkeypatch.setattr(web, '_log_queue', asyncio.Queue(maxsize=3))

    async def run():
        for i in range(5):
            await web._push(f'm{i}')
        out = []
        while not web._log_queue.empty():
            out.append((await web._log_queue.get())['message'])
        return out

    msgs = asyncio.run(run())
    assert msgs == ['m2', 'm3', 'm4']  # m0/m1 dropped, queue never exceeded 3
