"""Scan retention (core/retention.py) — prune artifact dirs, keep the index.

Pure planner + a filesystem apply step. Verifies keep-last / keep-days /
always-keep-newest, that apply deletes only the scan directory while keeping the
metadata entry (marked artifacts_pruned) and the history snapshot, idempotency,
and that the risk series survives a prune.
"""

from datetime import datetime

from core import retention
from core.project import ProjectStore


def _project(tmp_path, n=5):
    """A project with n recorded scans (dirs + metadata index + history)."""
    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    for i in range(1, n + 1):
        sid = f'2026010{i}_000000'
        scan_dir = project.start_scan(sid)
        (scan_dir / 'report.json').write_text('{}', encoding='utf-8')
        (scan_dir / 'big.bin').write_text('x' * 100, encoding='utf-8')
        report = {'scan_id': sid, 'finished_at': f'2026-01-0{i}T00:00:00',
                  'executive_summary': {'risk_level': 'Low', 'risk_score': i,
                                        'metrics': {'high': i}}}
        project.record_scan(scan_dir, report)
    return project


def test_no_policy_keeps_everything(tmp_path):
    project = _project(tmp_path, 4)
    plan = retention.plan_retention(project)
    assert plan['prune'] == [] and len(plan['keep']) == 4


def test_keep_last_prunes_older(tmp_path):
    project = _project(tmp_path, 5)
    plan = retention.plan_retention(project, keep_last=2)
    assert plan['keep'] == ['20260104_000000', '20260105_000000']
    assert plan['prune'] == ['20260101_000000', '20260102_000000', '20260103_000000']


def test_newest_always_kept_even_keep_last_zeroish(tmp_path):
    project = _project(tmp_path, 3)
    # keep_last=1 → only the newest survives
    plan = retention.plan_retention(project, keep_last=1)
    assert plan['keep'] == ['20260103_000000']
    assert '20260103_000000' not in plan['prune']


def test_keep_days_by_age(tmp_path):
    project = _project(tmp_path, 5)
    # "now" = Jan 5; keep_days=2 keeps Jan 3/4/5, prunes Jan 1/2
    now = datetime(2026, 1, 5, 0, 0, 0)
    plan = retention.plan_retention(project, keep_days=2, now=now)
    assert plan['prune'] == ['20260101_000000', '20260102_000000']
    assert set(plan['keep']) == {'20260103_000000', '20260104_000000',
                                 '20260105_000000'}


def test_apply_deletes_dir_keeps_index_and_history(tmp_path):
    project = _project(tmp_path, 4)
    plan = retention.plan_retention(project, keep_last=2)
    out = retention.apply_retention(project, plan)

    assert set(out['pruned']) == {'20260101_000000', '20260102_000000'}
    assert out['freed_bytes'] > 0 and out['missing'] == []
    # artifact dirs gone, kept ones remain
    assert not (project.root / 'scans' / '20260101_000000').exists()
    assert (project.root / 'scans' / '20260104_000000').exists()
    # metadata index entry kept + marked; history snapshot kept
    by_id = {s['id']: s for s in project.scans()}
    assert len(by_id) == 4
    assert by_id['20260101_000000']['artifacts_pruned'] is True
    assert 'artifacts_pruned' not in by_id['20260104_000000']
    assert (project.root / 'history' / '20260101_000000.json').exists()


def test_apply_is_idempotent(tmp_path):
    project = _project(tmp_path, 4)
    retention.prune_project(project, keep_last=2)
    # a second plan never re-lists already-pruned entries
    plan2 = retention.plan_retention(project, keep_last=2)
    assert plan2['prune'] == []
    out2 = retention.apply_retention(project, plan2)
    assert out2['pruned'] == []


def test_series_survives_prune(tmp_path):
    from core import timeline
    project = _project(tmp_path, 5)
    retention.prune_project(project, keep_last=2)
    series = timeline.build_series(project.scans())
    # all 5 points still present (index kept) → trend chart intact
    assert len(series) == 5
    assert [p['high'] for p in series] == [1, 2, 3, 4, 5]


def test_policy_from_settings_defaults_disabled():
    pol = retention.policy_from_settings({'retention': {}})
    assert pol['enabled'] is False
    pol2 = retention.policy_from_settings(
        {'retention': {'enabled': True, 'keep_last': 5, 'keep_days': 30}})
    assert pol2 == {'enabled': True, 'keep_last': 5, 'keep_days': 30}
