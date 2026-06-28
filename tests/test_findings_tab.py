"""Findings Management GUI tab (gui/tab_findings.py, F1 T1.5) — headless.

Threads are avoided the way the Dashboard tests do it: the off-GUI queries are
plain staticmethods exercised directly, and the populate/selection logic is
driven with ``_run_async`` stubbed out. The findings DB is the per-test temp
file from conftest's ``_isolate_findings_db`` fixture, so ``FindingsStore()``
inside the tab and inside the test point at the same store.
"""

from core.finding_fingerprint import scoped_id
from core.findings_store import FindingsStore
from gui.plugin_manager import default_manager
from gui.tab_findings import FindingsTabMixin
from tests.gui_test_helpers import FindingsHost


def _window(qapp):
    return FindingsHost()


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
    titles = [p.title for p in default_manager()]
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

def test_table_load_error_clears_stale_rows_detail_and_apply(qapp):
    w = _window(qapp)
    w._run_async = lambda *a, **k: None
    w._on_findings_table_loaded({
        'rows': [{'id': 'f-a', 'category': 'header', 'title': 'Weak CSP',
                  'severity': 'high', 'status': 'OPEN',
                  'first_seen_at': '2026-01-01T00:00:00',
                  'last_seen_at': '2026-01-02T00:00:00'}],
        'summary': {'total': 1, 'active': 1},
        'finding_chains': {'f-a': {'host': 'x.com'}},
        'project': 'p1',
    })
    w.findings_table.selectRow(0)
    assert w.btn_findings_apply.isEnabled()

    w._on_findings_table_loaded({'project': 'p1', 'error': 'boom'})

    assert w.findings_table.rowCount() == 0
    assert w.findings_detail.toPlainText() == ''
    assert not w.btn_findings_apply.isEnabled()
    assert w._findings_records == []
    assert w._findings_chains == {}
    assert 'boom' in w.findings_status.text()


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


# ── F-K3: asset/infra chain in the detail panel ───────────────────────────────

def test_query_findings_table_includes_chain(qapp):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    s = FindingsStore()
    s.upsert('pk', {'id': 'f-x', 'category': 'graphql', 'rule_id': 'introspection',
                    'title': 'GraphQL introspection', 'severity': 'high',
                    'evidence': {'location': 'api.acme.com/graphql'}})
    AssetStore().sync('pk', 's1', [
        Asset('subdomain', 'api.acme.com', attrs={'ip': '1.2.3.4'}),
        Asset('endpoint', 'api.acme.com/graphql')])
    out = FindingsTabMixin._query_findings_table('pk', None, None)
    sid = scoped_id('pk', 'f-x')
    chain = out['finding_chains'][sid]
    assert chain['endpoint'] == 'api.acme.com/graphql'
    assert chain['host'] == 'api.acme.com' and chain['ip'] == '1.2.3.4'


def test_query_findings_table_no_chain_for_all_projects(qapp):
    out = FindingsTabMixin._query_findings_table(None, None, None)
    assert out['finding_chains'] == {}          # correlation skipped for "all"


def test_finding_detail_renders_chain(qapp):
    w = _window(qapp)
    w._findings_chains = {'f-x': {'endpoint': 'api.acme.com/graphql',
                                  'host': 'api.acme.com', 'ip': '1.2.3.4',
                                  'asn': 'AS13335', 'asn_name': 'CF'}}
    w._show_finding_detail({'id': 'f-x', 'title': 't', 'category': 'graphql',
                            'severity': 'high', 'status': 'OPEN', 'evidence': {}})
    text = w.findings_detail.toPlainText()
    assert 'Цепочка' in text
    assert 'api.acme.com/graphql' in text and 'AS13335 (CF)' in text


# ── F-O3: finding object (description/impact/remediation) in the detail ────────

def test_finding_detail_shows_knowledge(qapp):
    w = _window(qapp)
    w._show_finding_detail({'id': 'f', 'title': 'Insecure cookie',
                            'category': 'cookie', 'severity': 'low',
                            'status': 'OPEN', 'evidence': {}})
    text = w.findings_detail.toPlainText()
    assert 'Описание' in text and 'Remediation' in text
    assert 'Secure' in text                       # cookie remediation from catalog


def test_finding_detail_prefers_producer_remediation(qapp):
    w = _window(qapp)
    w._show_finding_detail({'id': 'f', 'title': 'X', 'category': 'vuln',
                            'severity': 'high', 'status': 'OPEN',
                            'evidence': {'remediation': 'Patch to 2.0'}})
    assert 'Patch to 2.0' in w.findings_detail.toPlainText()


# ── KEV/EPSS exploitability badge (findings detail + in-list cue) ──────────────

def test_finding_detail_shows_kev_badge_and_tightening(qapp):
    w = _window(qapp)
    w._show_finding_detail({
        'id': 'f', 'title': 'Log4Shell', 'category': 'vuln', 'rule_id': 'CVE-2021-44228',
        'severity': 'low', 'status': 'OPEN', 'evidence': {},
        'threat': {'kev': True, 'epss_percentile': 0.99, 'tier': 'high'},
        'sla': {'applicable': True, 'sla_days': 30, 'base_sla_days': 120,
                'tightened_by': 'kev', 'breached': False, 'days_left': 25},
    })
    text = w.findings_detail.toPlainText()
    assert 'Exploitability' in text and 'KEV' in text and 'EPSS 99%' in text
    assert 'ужесточено: KEV' in text and '120' in text   # tightening explained


def test_finding_detail_no_badge_without_threat(qapp):
    w = _window(qapp)
    w._show_finding_detail({'id': 'f', 'title': 'Weak CSP', 'category': 'header',
                            'severity': 'high', 'status': 'OPEN', 'evidence': {}})
    assert 'Exploitability' not in w.findings_detail.toPlainText()


def test_populate_table_marks_kev_row_tooltip(qapp):
    w = _window(qapp)
    w._populate_findings_table([
        {'id': 'f-a', 'category': 'vuln', 'title': 'Log4Shell', 'severity': 'high',
         'status': 'OPEN', 'first_seen_at': '2026-01-01T00:00:00',
         'last_seen_at': '2026-01-02T00:00:00', 'threat': {'kev': True}},
    ])
    assert 'KEV' in w.findings_table.item(0, 2).toolTip()


def test_query_findings_table_annotates_threat_and_tightens_sla(qapp):
    from core.cve_store import CVEStore
    from core.finding_fingerprint import scoped_id
    cve = 'CVE-2021-44228'
    CVEStore().put_cve_threat(cve, {'kev': True})    # isolated per-test (conftest)
    s = FindingsStore()
    s.upsert('pk', {'id': 'f-kev', 'category': 'vuln', 'rule_id': cve,
                    'title': 'Log4Shell', 'severity': 'high', 'evidence': None})
    out = FindingsTabMixin._query_findings_table('pk', None, None)
    row = next(r for r in out['rows'] if r['id'] == scoped_id('pk', 'f-kev'))
    assert row['threat']['kev'] is True              # threat block attached for the badge
    assert row['sla']['tightened_by'] == 'kev'       # SLA clock tightened (30 → 8)
    assert row['sla']['sla_days'] == 8


# ── SARIF export (EPIC 16 F1) ───────────────────────────────────────────────────

def test_export_findings_sarif_writes_valid_file(qapp, tmp_path, monkeypatch):
    import json

    import gui.tab_findings as tf
    w = _window(qapp)
    w._findings_records = [
        {'id': 'f-a', 'project': 'p1', 'category': 'header', 'rule_id': 'csp',
         'title': 'Weak CSP', 'severity': 'high', 'status': 'OPEN',
         'evidence': {'location': 'https://x.com/'}}]
    out = tmp_path / 'out.sarif'
    monkeypatch.setattr(tf.QFileDialog, 'getSaveFileName',
                        staticmethod(lambda *a, **k: (str(out), '')))
    w._export_findings_sarif()
    doc = json.loads(out.read_text(encoding='utf-8'))
    assert doc['version'] == '2.1.0'
    assert doc['runs'][0]['results'][0]['ruleId'] == 'csp'
    assert doc['runs'][0]['tool']['driver']['version']   # APP_VERSION wired


def test_export_findings_sarif_empty_is_noop(qapp):
    w = _window(qapp)
    w._findings_records = []
    w._export_findings_sarif()
    assert 'Нечего экспортировать' in w.findings_status.text()
