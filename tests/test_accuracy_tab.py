"""Scan Accuracy GUI tab (gui/tab_accuracy.py, MODULE 1) — headless, thread-free.

Report-based (like the Timeline tab): the off-GUI queries are plain staticmethods
exercised directly against a project seeded under a tmp base, and the populate /
selection logic is driven with synthetic rows. The findings/assets DBs are
conftest's per-test temp files, so the stores the tab reads match what the test
seeds. Accuracy is per-project, display-only and read-only.
"""

from gui.tab_accuracy import AccuracyTabMixin
from gui.plugin_manager import default_manager
from tests.gui_test_helpers import AccuracyHost


def _window(qapp):
    return AccuracyHost()


def _seed_project(base):
    """One recorded scan whose report carries scannable entities (a technology +
    an infrastructure block), plus a persisted finding and asset for the slug, so
    accuracy_from_report yields a non-empty rollup."""
    import json

    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    from core.project import ProjectStore

    project = ProjectStore(base).get_or_create('https://x.com')
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {
        'scan_id': sid, 'finished_at': sid,
        'phases': {
            'recon': {'status': 'Success', 'data': {
                'technologies': [{'name': 'nginx', 'version': '1.18',
                                  'evidence_method': 'header', 'source': 'header'}],
                'infrastructure': {'asn': 'AS13335', 'ip': '1.1.1.1',
                                   'source': 'rdap'},
            }},
        },
    }
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)

    FindingsStore().upsert('x.com', {
        'id': 'f-1', 'category': 'graphql', 'rule_id': 'introspection',
        'title': 'GraphQL introspection', 'severity': 'high',
        'evidence': {'location': 'api.x.com/graphql'}})
    AssetStore().sync('x.com', sid, [Asset('domain', 'x.com')])
    return project


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_columns(qapp):
    w = _window(qapp)
    assert hasattr(w, '_accuracy_widget')
    assert w.acc_table.columnCount() == len(AccuracyTabMixin.ACCURACY_COLUMNS)


def test_accuracy_registered_in_tab_bar(qapp):
    titles = [p.title for p in default_manager()]
    assert 'Scan Accuracy' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_lists_scanned_projects(qapp, tmp_path):
    _seed_project(tmp_path)
    res = AccuracyTabMixin._query_acc_projects(str(tmp_path))
    assert any(p.get('slug') == 'x.com' for p in res['projects'])


def test_query_table_scores_entities(qapp, tmp_path):
    _seed_project(tmp_path)
    out = AccuracyTabMixin._query_acc_table(str(tmp_path), 'x.com')
    assert out['slug'] == 'x.com'
    items = out['items']
    assert items, 'expected scored entities'
    # ranked confidence-desc: each score >= the next.
    scores = [i['score'] for i in items]
    assert scores == sorted(scores, reverse=True)
    # the seeded technology + finding + asset all surface as entity types.
    types = {i['entity_type'] for i in items}
    assert {'technology', 'finding', 'asset'} <= types
    assert out['summary']['entities'] == len(items)


def test_query_table_unknown_project_is_clean(qapp, tmp_path):
    out = AccuracyTabMixin._query_acc_table(str(tmp_path), 'nope.com')
    assert 'error' in out and out['slug'] == 'nope.com'


# ── populate + project selector ────────────────────────────────────────────────

def test_on_loaded_fills_project_combo(qapp):
    w = _window(qapp)
    w._apply_accuracy = lambda *a, **k: None   # don't trigger stage-2 load
    w._on_acc_loaded({'projects': [
        {'slug': 'x.com', 'scan_count': 1},
        {'slug': 'y.com', 'scan_count': 2},
    ]})
    datas = [w.acc_project.itemData(i) for i in range(w.acc_project.count())]
    assert datas == ['x.com', 'y.com']


def test_empty_projects_shows_message(qapp):
    w = _window(qapp)
    w._on_acc_loaded({'projects': []})
    assert 'Нет проектов' in w.acc_status.text()
    assert w.acc_table.rowCount() == 0


def test_table_load_populates_rows_and_rollup(qapp):
    w = _window(qapp)
    w.acc_project.addItem('x.com', 'x.com')   # match the result's slug
    w._on_acc_table_loaded({'slug': 'x.com', 'items': [
        {'entity_type': 'technology', 'label': 'nginx 1.18', 'score': 90,
         'band': 'high', 'verification': 'header', 'source': ['header'],
         'evidence': ['header:Server']},
    ], 'summary': {'entities': 1, 'high_confidence': 1, 'avg_confidence': 90}})
    assert w.acc_table.rowCount() == 1
    assert w.acc_table.item(0, 0).text() == '90%'
    assert w.acc_table.item(0, 1).text() == 'high'
    assert w.acc_table.item(0, 3).text() == 'nginx 1.18'
    assert w.acc_rollup['entities'].text() == '1'
    assert w.acc_rollup['avg_confidence'].text() == '90%'


def test_stale_result_is_discarded(qapp):
    w = _window(qapp)
    w.acc_project.addItem('current.com', 'current.com')
    w._on_acc_table_loaded({'slug': 'other.com', 'items': [
        {'entity_type': 'asset', 'label': 'z.com', 'score': 50, 'band': 'medium'}],
        'summary': {'entities': 1}})
    assert w.acc_table.rowCount() == 0   # result for a non-selected project ignored


# ── selection / detail ──────────────────────────────────────────────────────────

def test_table_load_error_clears_stale_rows_and_rollup(qapp):
    w = _window(qapp)
    w.acc_project.addItem('x.com', 'x.com')
    w._on_acc_table_loaded({'slug': 'x.com', 'items': [
        {'entity_type': 'technology', 'label': 'nginx 1.18', 'score': 90,
         'band': 'high', 'verification': 'header', 'source': ['header'],
         'evidence': ['header:Server']},
    ], 'summary': {'entities': 1, 'high_confidence': 1, 'avg_confidence': 90}})
    w.acc_table.selectRow(0)
    assert w.acc_table.rowCount() == 1

    w._on_acc_table_loaded({'slug': 'x.com', 'error': 'boom'})

    assert w.acc_table.rowCount() == 0
    assert w.acc_detail.toPlainText() == ''
    assert w.acc_rollup['entities'].text() == '0'
    assert w.acc_rollup['avg_confidence'].text() == '0%'
    assert w._acc_records == []
    assert 'boom' in w.acc_status.text()


def test_selection_shows_evidence_and_factors(qapp):
    w = _window(qapp)
    w._populate_acc_table([{
        'entity_type': 'technology', 'label': 'nginx 1.18', 'score': 90,
        'band': 'high', 'verification': 'header', 'source': ['header'],
        'evidence': ['header:Server: nginx'],
        'factors': [{'factor': 'Метод детекта: header', 'points': 90}],
    }])
    w.acc_table.selectRow(0)
    text = w.acc_detail.toPlainText()
    assert 'nginx 1.18' in text
    assert 'header:Server: nginx' in text
    assert '+90' in text
