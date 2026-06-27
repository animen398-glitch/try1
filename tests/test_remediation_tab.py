"""Remediation GUI tab (gui/tab_remediation.py) — headless.

Mirrors test_criticality_tab / test_findings: off-GUI queries are plain
staticmethods exercised directly; populate/selection/write logic is driven with
``_run_async`` not needed (we call the handlers directly). The findings DB is the
per-test temp file from conftest's ``_isolate_findings_db`` fixture, so
``FindingsStore()`` inside the tab and the test share one store.
"""

from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from core.remediation import set_task
from gui.tab_remediation import RemediationTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed_findings(project='shop.com', n=2):
    s = FindingsStore()
    ids = []
    for i in range(n):
        dto = Finding(category='vuln', rule_id=f'r{i}', title=f'V{i}',
                      severity='high', location=f'https://h/{i}').to_store()
        ids.append(s.upsert(project, dto, scan_id='s1')['finding']['id'])
    return s, ids


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_remediation_widget')
    assert w.rem_table.columnCount() == len(RemediationTabMixin.REM_COLUMNS)


def test_remediation_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Remediation' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_lists_finding_projects(qapp):
    _seed_findings('shop.com', 2)
    res = RemediationTabMixin._query_rem_projects()
    names = {p['project'] for p in res['projects']}
    assert 'shop.com' in names


def test_query_table_returns_tasks(qapp):
    s, ids = _seed_findings('shop.com', 2)
    set_task(s, ids[0], status='in_progress', owner='alice')
    out = RemediationTabMixin._query_rem_table('shop.com')
    tasks = out['data']['tasks']
    assert len(tasks) == 1
    assert tasks[0]['finding_id'] == ids[0]
    assert tasks[0]['task']['owner'] == 'alice'
    assert out['data']['summary']['in_progress'] == 1


# ── populate + selection + edit ─────────────────────────────────────────────────

def test_on_loaded_fills_project_combo(qapp):
    w = _window(qapp)
    w._apply_rem_filter = lambda *a, **k: None
    w._on_rem_loaded({'projects': [{'project': 'shop.com', 'total': 2, 'active': 2}]})
    datas = [w.rem_project.itemData(i) for i in range(w.rem_project.count())]
    assert datas == ['shop.com']        # per-project, no "all"


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_rem_table_loaded({'project': 'shop.com', 'data': {
        'tasks': [{'finding_id': 'f1', 'title': 'V0', 'severity': 'high',
                   'category': 'vuln', 'finding_status': 'OPEN', 'updated_at': 't',
                   'task': {'status': 'open', 'owner': 'bob', 'due': '2026-07-01'},
                   'overdue': False, 'status_label': 'Открыто'}],
        'summary': {'total': 1, 'open': 1, 'in_progress': 0, 'done': 0, 'overdue': 0},
    }})
    assert w.rem_table.rowCount() == 1
    assert w.rem_table.item(0, 0).text() == 'Открыто'
    assert w.rem_table.item(0, 3).text() == 'bob'
    assert w.rem_rollup['total'].text() == '1'


def test_table_load_error_clears_stale_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_rem_table_loaded({'project': 'shop.com', 'data': {
        'tasks': [{'finding_id': 'f1', 'title': 'V0', 'severity': 'high',
                   'category': 'vuln', 'finding_status': 'OPEN', 'updated_at': 't',
                   'task': {'status': 'open', 'owner': 'bob', 'due': '2026-07-01'},
                   'overdue': False, 'status_label': 'Open'}],
        'summary': {'total': 1, 'open': 1, 'in_progress': 0, 'done': 0, 'overdue': 0},
    }})
    w.rem_table.selectRow(0)
    assert w.btn_rem_apply.isEnabled()

    w._on_rem_table_loaded({'project': 'shop.com', 'error': 'boom'})

    assert w.rem_table.rowCount() == 0
    assert w.rem_detail.toPlainText() == ''
    assert not w.btn_rem_apply.isEnabled()
    assert w.rem_rollup['total'].text() == '0'
    assert w._rem_records == []
    assert 'boom' in w.rem_status.text()


def test_selection_presets_edit_and_enables_apply(qapp):
    w = _window(qapp)
    w._populate_rem_table([{
        'finding_id': 'f1', 'title': 'V0', 'severity': 'high', 'category': 'vuln',
        'updated_at': 't', 'status_label': 'В работе',
        'task': {'status': 'in_progress', 'owner': 'carol', 'due': '2026-08-01'},
        'overdue': False,
    }])
    w.rem_table.selectRow(0)
    assert w.btn_rem_apply.isEnabled()
    assert w.rem_edit_status.currentData() == 'in_progress'
    assert w.rem_edit_owner.text() == 'carol'
    assert w.rem_edit_due.text() == '2026-08-01'


def test_write_rem_task_persists(qapp):
    s, ids = _seed_findings('shop.com', 1)
    set_task(s, ids[0], status='open')
    res = RemediationTabMixin._write_rem_task(ids[0], 'done', 'dave', '2026-09-01')
    assert res.get('ok')
    task = FindingsStore().get_remediation(ids[0])
    assert task['status'] == 'done' and task['owner'] == 'dave'


def test_seed_creates_tasks_for_top_findings(qapp):
    s, ids = _seed_findings('shop.com', 2)
    res = RemediationTabMixin._seed_rem_tasks('shop.com')
    assert res.get('created', 0) >= 1
    assert any(FindingsStore().get_remediation(i) for i in ids)
