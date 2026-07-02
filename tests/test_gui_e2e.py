"""End-to-end GUI flows — real button activations drive the full
click → handler → worker → callback → store/UI chain.

Unlike the per-method tab tests, these use the e2e hosts whose ``_run_async``
runs **inline** (no QThread) and trigger genuine ``clicked`` activations
(``QAbstractButton.click()`` — respects enabled-state and fires the connected
slot), then assert on real store state + widgets. Offline / headless (offscreen
Qt); the stores are isolated per test by the conftest fixtures.
"""

from core.findings_store import FindingsStore
from tests.gui_test_helpers import (
    EngagementsE2EHost, FindingsE2EHost, MissionsE2EHost,
)


# ── Findings: select a row, then assign / comment / change status by click ───────

def _seed_finding(project='shop.io'):
    fs = FindingsStore()
    fid = fs.upsert(project, {'id': 'fp1', 'category': 'vuln', 'rule_id': 'r',
                              'title': 't', 'severity': 'high'})['finding']['id']
    return fs, fid


def _findings_host_on_row():
    w = FindingsE2EHost()
    w._refresh_findings()                       # sync: loads projects + table inline
    assert w.findings_table.rowCount() >= 1
    w.findings_table.selectRow(0)               # enables the triage controls
    return w


def test_e2e_findings_assign_by_click(qapp):
    fs, fid = _seed_finding()
    w = _findings_host_on_row()
    w.findings_assignee.setText('alice')
    assert w.btn_findings_assign.isEnabled()
    w.btn_findings_assign.click()               # → _apply_finding_assign → store
    assert fs.get_assignee(fid) == 'alice'


def test_e2e_findings_comment_by_click(qapp):
    fs, fid = _seed_finding()
    w = _findings_host_on_row()
    w.findings_comment.setText('investigate')
    w.btn_findings_comment.click()
    assert [c['text'] for c in fs.comments(fid)] == ['investigate']


def test_e2e_findings_status_change_by_click(qapp):
    fs, fid = _seed_finding()
    w = _findings_host_on_row()
    w.findings_new_status.setCurrentIndex(w.findings_new_status.findData('FIXED'))
    assert w.btn_findings_apply.isEnabled()
    w.btn_findings_apply.click()                # → _apply_finding_status → store
    assert fs.get(fid)['status'] == 'FIXED'


def test_e2e_findings_assign_button_disabled_without_selection(qapp):
    _seed_finding()
    w = FindingsE2EHost()
    w._refresh_findings()
    # nothing selected yet → triage controls stay disabled (enable-state wiring)
    assert not w.btn_findings_assign.isEnabled()
    assert not w.btn_findings_apply.isEnabled()


# ── Missions: run a tool by click → finding ingested into the project ────────────

def _seed_mission(project='shop.io', actions=('headers_check',)):
    from core import pentest_mission as pm
    from core.mission_store import MissionStore
    mission = pm.create_mission(
        project, 'review',
        roe={'allowed_domains': [project], 'active_scan_enabled': True,
             'passive_only': False, 'authorized_by': 'client'},
        allowed_actions=list(actions))
    return MissionStore().save_mission(mission)


def test_e2e_missions_run_tool_by_click(qapp):
    _seed_mission()
    w = MissionsE2EHost()
    w._refresh_mission_projects()               # sync: projects → missions table
    assert w.mission_table.rowCount() >= 1
    w.mission_table.selectRow(0)
    w.mission_tool.setCurrentIndex(w.mission_tool.findData('header_audit'))
    w.mission_tool_evidence.setPlainText('{"url": "https://shop.io", "headers": {}}')
    assert w.btn_mission_tool_run.isEnabled()
    w.btn_mission_tool_run.click()              # → _run_mission_tool → ingest
    # header_audit on shop.io flags missing security headers → finding ingested
    assert FindingsStore().list_findings('shop.io')


def test_e2e_missions_fill_evidence_from_scan_by_click(qapp, tmp_path, monkeypatch):
    import json

    import core.config as config
    from core.project import ProjectStore
    # point the workspace base (used by evidence_from_project_scan) at a tmp tree
    monkeypatch.setattr(config, 'load_settings',
                        lambda: {'output_dir': str(tmp_path)})
    proj = ProjectStore(str(tmp_path)).get_or_create('https://shop.io')
    sid = '20260101_000000'
    d = proj.start_scan(sid)
    report = {'url': 'https://shop.io', 'finished_at': sid,
              'phases': {'subdomains': {'data': {
                  'results': [{'subdomain': 'a.shop.io'}]}}}}
    (d / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    proj.record_scan(d, report)

    _seed_mission(actions=('safe_active_probe',))
    w = MissionsE2EHost()
    w._refresh_mission_projects()
    w.mission_table.selectRow(0)
    w.mission_tool.setCurrentIndex(w.mission_tool.findData('safe_active_prober'))
    assert w.btn_mission_tool_evidence.isEnabled()
    w.btn_mission_tool_evidence.click()         # → fill evidence from the scan
    filled = json.loads(w.mission_tool_evidence.toPlainText())
    assert filled['subdomains'] == ['a.shop.io']


# ── Engagements: create + advance status by real button clicks ───────────────────

def _fill_engagement_create(w, *, client='Acme', project='shop.io'):
    w.engagement_create_client.setText(client)
    w.engagement_create_project.setText(project)
    w.engagement_create_domains.setText('shop.io')
    w.engagement_create_accepted.setChecked(True)      # so draft→authorized is legal
    w.engagement_create_authby.setText('CISO')


def test_e2e_engagement_create_by_click(qapp):
    from core.engagement_store import EngagementStore
    w = EngagementsE2EHost()
    _fill_engagement_create(w)
    w.btn_engagement_create.click()                    # → _do_create_engagement → store
    engagements = EngagementStore().list_engagements('shop.io')
    assert len(engagements) == 1
    assert engagements[0]['status'] == 'draft'


def test_e2e_engagement_advance_status_by_click(qapp):
    from core.engagement_store import EngagementStore
    w = EngagementsE2EHost()
    _fill_engagement_create(w)
    w.btn_engagement_create.click()                    # create + auto-refresh
    assert w.engagement_table.rowCount() >= 1
    w.engagement_table.selectRow(0)                    # fills the advance combo
    idx = w.engagement_advance_status.findData('authorized')
    assert idx >= 0                                    # draft→authorized offered
    w.engagement_advance_status.setCurrentIndex(idx)
    assert w.btn_engagement_advance.isEnabled()
    w.btn_engagement_advance.click()                   # → _do_advance_engagement → store
    assert EngagementStore().list_engagements('shop.io')[0]['status'] == 'authorized'
