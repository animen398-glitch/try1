"""IaC Config GUI tab (gui/tab_iac.py, EPIC NEXT F7 GUI tail) - headless."""

import json

from gui.plugin_manager import default_manager
from gui.tab_iac import IacTabMixin
from tests.gui_test_helpers import IacHost


def _window(qapp):
    return IacHost()


def test_tab_builds_with_tables(qapp):
    w = _window(qapp)
    assert hasattr(w, '_iac_widget')
    assert w.iac_findings.columnCount() == len(IacTabMixin.IAC_FINDING_COLUMNS)
    assert w.iac_technologies.columnCount() == len(IacTabMixin.IAC_TECH_COLUMNS)


def test_iac_registered_in_tab_bar(qapp):
    titles = [p.title for p in default_manager()]
    assert 'IaC Config' in titles


def test_query_iac_scan_reads_local_folder(qapp, tmp_path):
    (tmp_path / 'Dockerfile').write_text('FROM nginx:latest\n', encoding='utf-8')
    out = IacTabMixin._query_iac_scan(str(tmp_path))
    assert out['path'] == str(tmp_path)
    data = out['data']
    assert data['summary']['files'] == 1
    assert any(f['rule_id'] == 'iac-docker-unpinned'
               for f in data['findings'])


def test_demo_iac_path_is_preselected_without_autoscan(qapp, tmp_path):
    demo = tmp_path / 'demo_iac'
    demo.mkdir()

    class Host(IacHost):
        def __init__(self):
            super(IacHost, self).__init__()
            self.settings = {'output_dir': str(tmp_path)}
            self._build_iac_tab()

    w = Host()

    assert w.iac_path.text() == str(demo)
    assert 'Demo IaC sample selected' in w.iac_status.text()
    assert w.iac_findings.rowCount() == 0


def test_populate_iac_tables_and_rollup(qapp):
    w = _window(qapp)
    data = {
        'summary': {'files': 2, 'findings': 1, 'technologies': 1,
                    'skipped_yaml': 0},
        'findings': [{
            'severity': 'High',
            'rule_id': 'iac-compose-privileged',
            'title': 'Privileged container',
            'location': 'compose.yml',
            'detail': 'service api runs privileged',
        }],
        'technologies': [{'name': 'nginx', 'version': 'latest'}],
    }
    w._iac_result = data
    w._populate_iac(data)

    assert w.iac_rollup['files'].text() == '2'
    assert w.iac_findings.rowCount() == 1
    assert w.iac_findings.item(0, 1).text() == 'iac-compose-privileged'
    assert w.iac_technologies.rowCount() == 1
    assert w.iac_technologies.item(0, 0).text() == 'nginx'


def test_scan_error_clears_stale_iac_tables_and_export(qapp):
    w = _window(qapp)
    data = {
        'summary': {'files': 2, 'findings': 1, 'technologies': 1},
        'findings': [{
            'severity': 'High',
            'rule_id': 'iac-compose-privileged',
            'title': 'Privileged container',
            'location': 'compose.yml',
            'detail': 'service api runs privileged',
        }],
        'technologies': [{'name': 'nginx', 'version': 'latest'}],
    }
    w._iac_result = data
    w._populate_iac(data)
    w.btn_iac_export.setEnabled(True)

    w._on_iac_scan_done({'path': 'compose.yml', 'error': 'boom'})

    assert not w.btn_iac_export.isEnabled()
    assert w.iac_findings.rowCount() == 0
    assert w.iac_technologies.rowCount() == 0
    assert w.iac_detail.toPlainText() == ''
    assert w.iac_rollup['files'].text() == '0'
    assert w._iac_result == {}
    assert 'boom' in w.iac_status.text()


def test_selection_shows_finding_detail(qapp):
    w = _window(qapp)
    data = {
        'summary': {},
        'findings': [{
            'severity': 'Medium',
            'rule_id': 'iac-docker-root',
            'title': 'Container runs as root',
            'location': 'Dockerfile',
            'detail': 'no non-root USER set',
        }],
        'technologies': [],
    }
    w._iac_result = data
    w._populate_iac(data)
    w.iac_findings.selectRow(0)
    text = w.iac_detail.toPlainText()
    assert 'iac-docker-root' in text
    assert 'no non-root USER set' in text


def test_iac_json_payload_is_valid(qapp):
    payload = IacTabMixin._iac_json_payload({'summary': {'files': 1}})
    assert json.loads(payload)['summary']['files'] == 1
