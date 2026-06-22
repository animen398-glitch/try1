"""Remediation Tasks (EPIC NEXT F4).

A remediation task is event-sourced over finding_events (one REMEDIATION event per
change; the task = the latest event's payload — no second table). core/remediation.py
owns the vocab, partial-update merge, overdue derivation and the rollup. Pure /
offline. The default FindingsStore() is isolated per-test by conftest.
"""

from datetime import datetime, timedelta

from core import remediation as rem
from core.findings_adapter import Finding
from core.findings_store import FindingsStore


def _seed_finding(store, project='site.com', rule='x', sev='high'):
    dto = Finding(category='vuln', rule_id=rule, title=f'V {rule}', severity=sev,
                  location=f'https://h/{rule}').to_store()
    return store.upsert(project, dto, scan_id='s1')['finding']['id']


# ── vocab / merge / overdue ───────────────────────────────────────────────────

def test_normalize_and_merge_task():
    assert rem.normalize_status('IN_PROGRESS') == 'in_progress'
    assert rem.normalize_status('bogus') is None
    assert rem.normalize_task({})['status'] == 'open'           # default
    assert rem.normalize_task({'status': 'done', 'owner': ' a '}) == {
        'status': 'done', 'owner': 'a'}

    base = {'status': 'open', 'owner': 'alice', 'due': '2026-07-01'}
    merged = rem.merge_task(base, {'status': 'in_progress', 'note': 'wip'})
    assert merged == {'status': 'in_progress', 'owner': 'alice',
                      'due': '2026-07-01', 'note': 'wip'}
    # explicit empty string clears a field; None leaves it.
    assert 'owner' not in rem.merge_task(base, {'owner': ''})


def test_is_overdue():
    past, future = '2000-01-01', '2999-01-01'
    assert rem.is_overdue({'status': 'open', 'due': past}) is True
    assert rem.is_overdue({'status': 'done', 'due': past}) is False   # done
    assert rem.is_overdue({'status': 'open', 'due': future}) is False
    assert rem.is_overdue({'status': 'open'}) is False                # no due
    # date-only due is treated as end of that day
    today = datetime.now()
    assert rem.is_overdue({'status': 'open',
                           'due': (today - timedelta(days=2)).date().isoformat()})


# ── store primitives (event-sourced, latest wins) ─────────────────────────────

def test_store_set_get_remediation_latest_wins(tmp_path):
    store = FindingsStore(tmp_path / 'f.db')
    fid = _seed_finding(store)
    assert store.get_remediation(fid) is None
    store.set_remediation(fid, {'status': 'open'})
    store.set_remediation(fid, {'status': 'in_progress', 'owner': 'bob'})
    assert store.get_remediation(fid) == {'status': 'in_progress', 'owner': 'bob'}
    rows = store.remediations('site.com')
    assert len(rows) == 1 and rows[0]['finding_id'] == fid
    assert rows[0]['task']['status'] == 'in_progress'
    assert rows[0]['severity'] == 'high'


# ── set_task / auto_create / load ─────────────────────────────────────────────

def test_set_task_partial_update(tmp_path):
    store = FindingsStore(tmp_path / 'f.db')
    fid = _seed_finding(store)
    rem.set_task(store, fid, status='open', owner='alice')
    task = rem.set_task(store, fid, status='in_progress')   # keeps owner
    assert task == {'status': 'in_progress', 'owner': 'alice'}


def test_auto_create_tasks_is_idempotent(tmp_path):
    store = FindingsStore(tmp_path / 'f.db')
    f1 = _seed_finding(store, rule='a')
    f2 = _seed_finding(store, rule='b')
    assert set(rem.auto_create_tasks(store, [f1, f2])) == {f1, f2}
    assert rem.auto_create_tasks(store, [f1, f2]) == []     # already have tasks
    assert store.get_remediation(f1)['status'] == 'open'


def test_load_remediation_summary_and_overdue_sort(tmp_path):
    store = FindingsStore(tmp_path / 'f.db')
    f1 = _seed_finding(store, rule='a')
    f2 = _seed_finding(store, rule='b')
    f3 = _seed_finding(store, rule='c')
    rem.set_task(store, f1, status='done')
    rem.set_task(store, f2, status='open', due='2000-01-01')      # overdue
    rem.set_task(store, f3, status='in_progress')
    out = rem.load_remediation('site.com', store=store)
    assert out['summary'] == {'total': 3, 'overdue': 1, 'open': 1,
                              'in_progress': 1, 'done': 1}
    assert out['tasks'][0]['finding_id'] == f2 and out['tasks'][0]['overdue']


def test_seed_from_intelligence_creates_tasks_for_top_findings():
    # Uses the conftest-isolated default store shared with load_intelligence.
    store = FindingsStore()
    fid = _seed_finding(store, project='shop.com', rule='sqli', sev='critical')
    created = rem.seed_from_intelligence('shop.com', top_n=5, store=store)
    assert fid in created
    assert store.get_remediation(fid)['status'] == 'open'


# ── web read-parity ───────────────────────────────────────────────────────────

def test_web_remediation_view():
    import remote.web_app as web
    store = FindingsStore()
    fid = _seed_finding(store, project='site.com')
    rem.set_task(store, fid, status='in_progress', owner='alice')
    view = web._remediation_view('site.com')
    assert view['summary']['total'] == 1
    assert view['tasks'][0]['task']['owner'] == 'alice'
    assert web._remediation_view(None) == {'tasks': [], 'summary': {}}


# ── CLI smoke ─────────────────────────────────────────────────────────────────

def test_cli_auto_list_set(tmp_path):
    import remediation_cli
    store = FindingsStore()
    fid = _seed_finding(store, project='site.com', sev='critical')
    base = ['--output', str(tmp_path)]
    assert remediation_cli.main(base + ['auto', 'site.com', '--top', '5']) == 0
    assert store.get_remediation(fid) is not None
    assert remediation_cli.main(base + ['set', 'site.com', fid,
                                        '--status', 'done']) == 0
    assert store.get_remediation(fid)['status'] == 'done'
    assert remediation_cli.main(base + ['list', 'site.com']) == 0
