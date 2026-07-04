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
    AssetsE2EHost, AuditRunsE2EHost, CriticalityE2EHost, EngagementsE2EHost,
    FindingsE2EHost, IacE2EHost, MissionsE2EHost, OverviewE2EHost,
    RemediationE2EHost,
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


# ── Remediation: seed tasks + edit a task by real button clicks ──────────────────

def _seed_rem_findings(project='shop.io', n=2):
    fs = FindingsStore()
    ids = []
    for i in range(n):
        fid = fs.upsert(project, {'id': f'rp{i}', 'category': 'vuln',
                                  'rule_id': f'r{i}', 'title': f'V{i}',
                                  'severity': 'high'})['finding']['id']
        ids.append(fid)
    return fs, ids


def test_e2e_remediation_seed_by_click(qapp):
    fs, ids = _seed_rem_findings()
    w = RemediationE2EHost()
    w._refresh_remediation()                    # sync: projects → table inline
    assert w.rem_project.currentData() == 'shop.io'
    assert w.btn_rem_seed.isEnabled()
    w.btn_rem_seed.click()                       # → _seed_remediation → store
    # top-priority findings now have tracked remediation tasks
    assert any(fs.get_remediation(i) for i in ids)


def test_e2e_remediation_edit_task_by_click(qapp):
    from core.remediation import set_task
    fs, ids = _seed_rem_findings(n=1)
    set_task(fs, ids[0], status='open')
    w = RemediationE2EHost()
    w._refresh_remediation()
    assert w.rem_table.rowCount() >= 1
    w.rem_table.selectRow(0)                     # fills edit row, enables apply
    assert w.btn_rem_apply.isEnabled()
    w.rem_edit_status.setCurrentIndex(w.rem_edit_status.findData('done'))
    w.rem_edit_owner.setText('dana')
    w.btn_rem_apply.click()                      # → _apply_remediation_edit → store
    task = fs.get_remediation(ids[0])
    assert task['status'] == 'done' and task['owner'] == 'dana'


# ── Audit Runs: run a client-safe audit by click → persisted to the store ────────

def test_e2e_audit_run_by_click(qapp):
    from core.audit_store import AuditRunStore
    fs = FindingsStore()
    fs.upsert('shop.io', {'id': 'ap1', 'category': 'vuln', 'rule_id': 'r',
                          'title': 't', 'severity': 'high'})
    w = AuditRunsE2EHost()
    w._refresh_audit_projects()                  # sync: project combo populated
    assert w.audit_project.currentData() == 'shop.io'
    assert w.btn_audit_start.isEnabled()
    # default ROE is passive-only with no active checks — offline, no target traffic
    w.btn_audit_start.click()                    # → _query_audit_run → AuditRunStore
    assert AuditRunStore().list_runs('shop.io')


# ── Overview: assign a company to a project by real button click ─────────────────

def _seed_overview_project(base, slug_url='https://x.com'):
    import json

    from core.project import ProjectStore
    project = ProjectStore(base).get_or_create(slug_url)
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {'scan_id': sid, 'finished_at': sid, 'warnings': [],
              'executive_summary': {'risk_level': 'Low', 'risk_score': 10,
                                    'risk_100': 10, 'metrics': {'risk_100': 10}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)
    return project


def test_e2e_overview_assign_company_by_click(qapp, tmp_path):
    from core.company import CompanyRegistry
    from core.project import ProjectStore
    _seed_overview_project(str(tmp_path))
    w = OverviewE2EHost()
    w.settings = {'output_dir': str(tmp_path)}   # _overview_base() reads this
    w._refresh_overview()                         # sync: portfolio → table
    assert w.overview_table.rowCount() >= 1
    w.overview_table.selectRow(0)                 # _selected_overview_slug() → 'x.com'
    w.overview_assign_company.setEditText('Acme')
    w.btn_assign.click()                          # → _do_assign → registry + project
    assert any(c['name'] == 'Acme' for c in CompanyRegistry().list())
    assert ProjectStore(str(tmp_path)).get('x.com').get_company()   # slug now set


# ── Assets: the load → select → detail read chain (row-selection activation) ─────

def test_e2e_assets_load_and_select_shows_detail(qapp):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    AssetStore().sync('p1', 's1', [Asset('subdomain', 'api.x.com')])
    w = AssetsE2EHost()
    w._refresh_assets()                           # sync: projects → filter → table
    assert w.assets_table.rowCount() >= 1
    w.assets_table.selectRow(0)                   # itemSelectionChanged → detail
    assert 'api.x.com' in w.assets_detail.toPlainText()


# ── Criticality: set the project business context by real button click ───────────

def test_e2e_criticality_set_business_default_by_click(qapp, tmp_path):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.business_context import show_business_context
    from core.project import ProjectStore
    AssetStore().sync('x.com', 's1', [Asset('subdomain', 'api.x.com')])
    w = CriticalityE2EHost()
    w.settings = {'output_dir': str(tmp_path)}    # _crit_base() reads this
    w._refresh_criticality()                       # sync: projects → combo
    assert w.crit_project.currentData() == 'x.com'
    w.biz_default_crit.setCurrentIndex(w.biz_default_crit.findData('high'))
    w.biz_default_sens.setCurrentIndex(w.biz_default_sens.findData('confidential'))
    w.biz_apply.click()                            # → _write_business → metadata.json
    ctx = show_business_context(
        ProjectStore(str(tmp_path)), 'x.com')['business_context']
    assert ctx['default']['criticality'] == 'high'
    assert ctx['default']['data_sensitivity'] == 'confidential'


# ── IaC: scan a local path by click → findings table populates ───────────────────

def test_e2e_iac_scan_by_click(qapp, tmp_path):
    dockerfile = tmp_path / 'Dockerfile'
    dockerfile.write_text(
        'FROM node:latest\nADD https://example.com/x.tar.gz /tmp/\n',
        encoding='utf-8')
    w = IacE2EHost()
    w.iac_path.setText(str(dockerfile))
    assert w.btn_iac_scan.isEnabled()
    w.btn_iac_scan.click()                         # → _query_iac_scan → scan_path
    # unpinned FROM + remote ADD are both flagged → the findings table has rows
    assert w.iac_findings.rowCount() >= 1
    assert w.btn_iac_export.isEnabled()            # export enabled once results exist
