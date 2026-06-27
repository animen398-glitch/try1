"""T9: a CollectionRunner scan never leaves an orphaned scan dir — if finalization
crashes, run() still writes a readable report.json (status Error) and re-raises.
Offline, no network (the pipeline is replaced by a stub that fails)."""
import json

import pytest

from core.collection_runner import CollectionRunner


def test_persist_error_report_writes_error_json(tmp_path):
    report = {'project_dir': str(tmp_path), 'url': 'http://x', 'phases': {}}
    CollectionRunner._persist_error_report(report, RuntimeError('boom'))
    data = json.loads((tmp_path / 'report.json').read_text(encoding='utf-8'))
    assert data['status'] == 'Error'
    assert 'boom' in data['error']
    assert data['report_json'].endswith('report.json')


def test_persist_error_report_noop_without_dir():
    CollectionRunner._persist_error_report({}, RuntimeError('x'))  # must not raise


def test_run_persists_error_report_on_finalization_failure(tmp_path, monkeypatch):
    runner = CollectionRunner()
    scan_dir = tmp_path / 'Projects' / 'x' / 'scans' / 's1'
    scan_dir.mkdir(parents=True)

    def boom(url, base):
        # Mimic _run_impl failing during finalization, after the scan dir and the
        # in-progress report have been registered on the runner.
        runner._active_operation = (None, None)
        runner._active_report = {'project_dir': str(scan_dir), 'url': url,
                                 'phases': {}}
        raise RuntimeError('finalize boom')

    monkeypatch.setattr(runner, '_run_impl', boom)
    with pytest.raises(RuntimeError, match='finalize boom'):
        runner.run('http://x', str(tmp_path))

    data = json.loads((scan_dir / 'report.json').read_text(encoding='utf-8'))
    assert data['status'] == 'Error'
    assert 'finalize boom' in data['error']
