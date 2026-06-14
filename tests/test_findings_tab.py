"""Findings Management GUI tab (gui/tab_findings.py, F1 T1.5) — headless.

Threads are avoided the way the Dashboard tests do it: the off-GUI queries are
plain staticmethods exercised directly, and the populate/selection logic is
driven with ``_run_async`` stubbed out. The findings DB is the per-test temp
file from conftest's ``_isolate_findings_db`` fixture, so ``FindingsStore()``
inside the tab and inside the test point at the same store.
"""

from core.finding_fingerprint import scoped_id
from core.findings_store import FindingsStore
from gui.tab_findings import FindingsTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed():
    s = FindingsStore()
    s.upsert('p1', {'id': 'f-a', 'category': 'header', 'rule_id': 'csp',
                    'title': 'Weak CSP', 'severity': 'high',
                    'evidence': {'location': 'https://x.com/'}})
    s.upsert('p1', {'id': 'f-b', 'category': 'cookie', 'rule_id': 'sess',
                    'title': 'Insecure cookie', 'severity': 'low'})
    s.upsert('p2', {'id': 'f-c', 'category': 'secret', 'rule_id': 'aws',
                    'title': 'AWS key', 'severity': 'critical'})
    return s


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_findings_widget')
    assert (w.findings_table.columnCount()
            == len(FindingsTabMixin.FINDINGS_COLUMNS))
    assert not w.btn_findings_apply.isEnabled()   # nothing selected yet


def test_findings_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Findings' in titles


# ── off-GUI queries read the store ─────────────────────────────────────────────

def test_query_findings_lists_projects(qapp):
    _seed()
    res = FindingsTabMixin._query_findings()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 2
    assert by_name['p2']['total'] == 1


def test_query_table_filters_by_project_and_severity(qapp):
    _seed()
    all_p1 = FindingsTabMixin._query_findings_table('p1', None, None)
    assert {r['title'] for r in all_p1['rows']} == {'Weak CSP', 'Insecure cookie'}
    assert all_p1['summary']['total'] == 2
    high_p1 = FindingsTabMixin._query_findings_table('p1', None, 'high')
    assert {r['title'] for r in high_p1['rows']} == {'Weak CSP'}


# ── populate + project selector ────────────────────────────────────────────────

def test_on_findings_loaded_fills_project_combo(qapp):
    w = _window(qapp)
    w._on_findings_loaded({'projects': [
        {'project': 'p1', 'total': 2, 'active': 2},
        {'project': 'p2', 'total': 1, 'active': 1},
    ]})
    # "Все проекты" + the two projects.
    datas = [w.findings_project.itemData(i)
             for i in range(w.findings_project.count())]
    assert datas == [None, 'p1', 'p2']


def test_populate_table_rows_and_status_label(qapp):
    w = _window(qapp)
    w._populate_findings_table([
        {'id': 'f-a', 'category': 'header', 'title': 'Weak CSP',
         'severity': 'high', 'status': 'OPEN',
         'first_seen_at': '2026-01-01T00:00:00',
         'last_seen_at': '2026-01-02T00:00:00'},
    ])
    assert w.findings_table.rowCount() == 1
    assert w.findings_table.item(0, 2).text() == 'Weak CSP'
    assert w.findings_table.item(0, 3).text() == 'Открыто'   # STATUS_LABELS
    assert w.findings_table.item(0, 4).text() == '2026-01-01'


# ── selection wiring (threads stubbed) ─────────────────────────────────────────

def test_selection_enables_apply_and_preselects_status(qapp):
    w = _window(qapp)
    w._run_async = lambda *a, **k: None     # don't spawn the events worker
    w._populate_findings_table([
        {'id': 'f-c', 'category': 'secret', 'title': 'AWS key',
         'severity': 'critical', 'status': 'IGNORED',
         'evidence': {'location': 'https://x.com/'},
         'first_seen_at': '2026-01-01', 'last_seen_at': '2026-01-01'},
    ])
    w.findings_table.selectRow(0)
    assert w.btn_findings_apply.isEnabled()
    assert w.findings_new_status.currentData() == 'IGNORED'   # preselected
    assert 'AWS key' in w.findings_detail.toPlainText()
    assert 'https://x.com/' in w.findings_detail.toPlainText()


# ── status change writes through to the store ──────────────────────────────────

def test_write_status_persists(qapp):
    s = _seed()
    # The GUI passes the scoped id it got from a listed row, not the bare one.
    fid = scoped_id('p1', 'f-a')
    res = FindingsTabMixin._write_finding_status(fid, 'FALSE_POSITIVE',
                                                 'not exploitable')
    assert res == {'ok': True}
    row = s.get(fid)
    assert row['status'] == 'FALSE_POSITIVE' and row['status_source'] == 'user'
    assert s.events(fid)[-1]['note'] == 'not exploitable'
