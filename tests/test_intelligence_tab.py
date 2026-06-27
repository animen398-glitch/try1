"""Priorities / Core Intelligence GUI tab (gui/tab_intelligence.py) — headless.

Mirrors test_assets_tab: off-GUI queries are plain staticmethods exercised
directly, and populate/selection logic is driven with ``_run_async`` stubbed out.
The findings DB is the per-test temp file from conftest's ``_isolate_findings_db``
fixture, so ``FindingsStore()`` inside the tab and inside the test share one store.
Intelligence is per-project and read-only — there is no triage control to test.
"""

from core.findings_store import FindingsStore
from gui.tab_intelligence import IntelligenceTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed():
    s = FindingsStore()
    s.upsert('p1', {'id': 'f-1', 'category': 'graphql', 'rule_id': 'introspection',
                    'title': 'GraphQL introspection', 'severity': 'high',
                    'evidence': {'location': 'api.x.com/graphql'}})
    s.upsert('p1', {'id': 'f-2', 'category': 'cookie', 'rule_id': 'weak',
                    'title': 'Weak cookie', 'severity': 'medium',
                    'evidence': {'location': 'x.com'}})
    return s


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_intel_widget')
    assert w.intel_table.columnCount() == len(IntelligenceTabMixin.INTEL_COLUMNS)


def test_priorities_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Priorities' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_lists_findings_projects(qapp):
    _seed()
    res = IntelligenceTabMixin._query_intel_projects()
    by_name = {p['project']: p for p in res['projects']}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 2


def test_query_table_ranks_by_priority(qapp):
    _seed()
    out = IntelligenceTabMixin._query_intel_table('p1')
    items = out['intel']['items']
    # high severity outranks medium → it comes first.
    assert items[0]['title'] == 'GraphQL introspection'
    assert items[0]['priority'] >= items[1]['priority']
    assert all('confidence' in i and 'explanation' in i for i in items)


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo_without_all_entry(qapp):
    w = _window(qapp)
    w._apply_intel_filter = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_intel_loaded({'projects': [
        {'project': 'p1', 'total': 2, 'active': 2},
        {'project': 'p2', 'total': 1, 'active': 1},
    ]})
    datas = [w.intel_project.itemData(i)
             for i in range(w.intel_project.count())]
    assert datas == ['p1', 'p2']            # per-project: no "all projects" None


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_intel_loaded({'projects': []})
    assert 'Нет проектов' in w.intel_status.text()
    assert w.intel_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_intel_table_loaded({'project': 'p1', 'intel': {
        'items': [{'priority': 73, 'confidence': 85, 'confidence_band': 'high',
                   'severity': 'high', 'category': 'graphql',
                   'title': 'GraphQL introspection'}],
        'summary': {'findings': 1, 'high_confidence': 1, 'top_priority': 73},
    }})
    assert w.intel_table.rowCount() == 1
    assert w.intel_table.item(0, 0).text() == '73'
    assert w.intel_table.item(0, 2).text() == 'high'
    assert w.intel_table.item(0, 4).text() == 'GraphQL introspection'
    assert w.intel_rollup['findings'].text() == '1'
    assert w.intel_rollup['top_priority'].text() == '73'


# ── selection / detail ──────────────────────────────────────────────────────────

def test_table_load_error_clears_stale_rows_and_rollup(qapp):
    w = _window(qapp)
    w._on_intel_table_loaded({'project': 'p1', 'intel': {
        'items': [{'priority': 73, 'confidence': 85, 'confidence_band': 'high',
                   'severity': 'high', 'category': 'graphql',
                   'title': 'GraphQL introspection'}],
        'summary': {'findings': 1, 'high_confidence': 1, 'top_priority': 73},
    }})
    w.intel_table.selectRow(0)
    assert w.intel_table.rowCount() == 1

    w._on_intel_table_loaded({'project': 'p1', 'error': 'boom'})

    assert w.intel_table.rowCount() == 0
    assert w.intel_detail.toPlainText() == ''
    assert w.intel_rollup['findings'].text() == '0'
    assert w._intel_records == []
    assert 'boom' in w.intel_status.text()


def test_selection_shows_explanation_and_factors(qapp):
    w = _window(qapp)
    w._populate_intel_table([{
        'priority': 73, 'confidence': 85, 'confidence_band': 'high',
        'severity': 'high', 'category': 'graphql',
        'title': 'GraphQL introspection',
        'explanation': {'description': 'Schema exposed', 'impact': 'recon',
                        'remediation': 'disable introspection'},
        'priority_factors': [{'factor': 'Severity high × confidence 85%',
                              'points': 30}],
        'confidence_factors': [{'factor': 'Базовая (категория «graphql»)',
                                'points': 85}],
    }])
    w.intel_table.selectRow(0)
    text = w.intel_detail.toPlainText()
    assert 'Schema exposed' in text
    assert 'disable introspection' in text
    assert '+30' in text and '+85' in text
