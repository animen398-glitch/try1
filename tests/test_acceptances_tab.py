"""Risk Acceptances GUI tab (gui/tab_acceptances.py) — headless.

Mirrors test_remediation_tab: off-GUI queries are plain staticmethods exercised
directly; populate/selection/revoke logic is driven on the lightweight host. The
findings DB is the per-test temp file from conftest's ``_isolate_findings_db``
fixture, so ``FindingsStore()`` inside the tab and the test share one store.
"""

from core.findings_adapter import Finding
from core.findings_store import FindingsStore
from gui.tab_acceptances import AcceptancesTabMixin
from tests.gui_test_helpers import AcceptancesHost


def _seed(project='shop.com', n=2):
    s = FindingsStore()
    ids = []
    for i in range(n):
        dto = Finding(category='vuln', rule_id=f'r{i}', title=f'V{i}',
                      severity='high', location=f'https://h/{i}').to_store()
        ids.append(s.upsert(project, dto, scan_id='s1')['finding']['id'])
    return s, ids


# ── build / registration ────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = AcceptancesHost()
    assert hasattr(w, '_acceptances_widget')
    assert w.acc_table.columnCount() == len(AcceptancesTabMixin.ACC_COLUMNS)


def test_acceptances_registered_in_tab_bar(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Risk Acceptances' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_table_returns_only_accepted(qapp):
    s, ids = _seed('shop.com', 2)
    s.accept_risk(ids[0], reason='low', approver='ciso', until='2099-01-01')
    out = AcceptancesTabMixin._query_acc_table('shop.com')
    assert [r['finding_id'] for r in out['rows']] == [ids[0]]
    assert out['rows'][0]['acceptance']['approver'] == 'ciso'


# ── populate + rollup ────────────────────────────────────────────────────────────

def test_table_load_populates_rows_and_rollup(qapp):
    w = AcceptancesHost()
    w._on_acc_table_loaded({'project': 'shop.com', 'rows': [
        {'finding_id': 'f1', 'title': 'V0', 'severity': 'high', 'category': 'vuln',
         'finding_status': 'OPEN', 'updated_at': 't',
         'acceptance': {'accepted': True, 'expired': False, 'reason': 'r',
                        'approver': 'bob', 'until': '2099-01-01'}},
        {'finding_id': 'f2', 'title': 'V1', 'severity': 'low', 'category': 'vuln',
         'finding_status': 'OPEN', 'updated_at': 't',
         'acceptance': {'accepted': True, 'expired': True, 'reason': 'r',
                        'approver': 'bob', 'until': '2000-01-01'}},
    ]})
    assert w.acc_table.rowCount() == 2
    assert w.acc_rollup['total'].text() == '2'
    assert w.acc_rollup['active'].text() == '1'
    assert w.acc_rollup['expired'].text() == '1'
    assert 'истекли: 1' in w.acc_status.text()


def test_expired_only_filter_narrows_table_but_not_rollup(qapp):
    w = AcceptancesHost()
    w._on_acc_table_loaded({'project': 'shop.com', 'rows': [
        {'finding_id': 'f1', 'title': 'V0', 'severity': 'high', 'category': 'vuln',
         'finding_status': 'OPEN', 'updated_at': 't',
         'acceptance': {'accepted': True, 'expired': False, 'reason': 'r',
                        'approver': 'bob', 'until': '2099-01-01'}},
        {'finding_id': 'f2', 'title': 'V1', 'severity': 'low', 'category': 'vuln',
         'finding_status': 'OPEN', 'updated_at': 't',
         'acceptance': {'accepted': True, 'expired': True, 'reason': 'r',
                        'approver': 'bob', 'until': '2000-01-01'}},
    ]})
    assert w.acc_table.rowCount() == 2                      # both shown by default
    w.acc_expired_only.setChecked(True)                    # → only the lapsed one
    assert w.acc_table.rowCount() == 1
    assert [r['finding_id'] for r in w._acc_records] == ['f2']
    # rollup still reflects the whole set, not the filtered view
    assert w.acc_rollup['total'].text() == '2'
    assert w.acc_rollup['expired'].text() == '1'
    w.acc_expired_only.setChecked(False)
    assert w.acc_table.rowCount() == 2


def test_selection_enables_revoke_and_shows_detail(qapp):
    w = AcceptancesHost()
    w._populate_acc_table([{
        'finding_id': 'f1', 'title': 'V0', 'severity': 'high', 'category': 'vuln',
        'finding_status': 'OPEN', 'updated_at': 't',
        'acceptance': {'accepted': True, 'expired': True, 'reason': 'risk ok',
                       'approver': 'carol', 'until': '2000-01-01'}}])
    w.acc_table.selectRow(0)
    assert w.btn_acc_revoke.isEnabled()
    assert 'carol' in w.acc_detail.toPlainText()
    assert 'ИСТЕКЛО' in w.acc_detail.toPlainText()


# ── write: revoke ────────────────────────────────────────────────────────────────

def test_write_acc_revoke_clears(qapp):
    s, ids = _seed('shop.com', 1)
    s.accept_risk(ids[0], until='2099-01-01')
    res = AcceptancesTabMixin._write_acc_revoke(ids[0])
    assert res.get('ok')
    assert s.risk_acceptance_state(ids[0])['accepted'] is False
