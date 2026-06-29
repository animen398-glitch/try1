"""Tests for the Continuous Monitoring CLI (monitor_cli.py)."""

import json

from core.project import ProjectStore, project_slug
import monitor_cli as cli


def test_cmd_enable_creates_schedule(tmp_path):
    store = ProjectStore(tmp_path)
    out = cli.cmd_enable(store, 'https://example.com', 'weekly')
    assert out['slug'] == 'example.com'
    project = store.get('example.com')
    mon = project.get_monitor()
    assert mon['enabled'] is True and mon['interval'] == 'weekly'


def test_cmd_disable(tmp_path):
    store = ProjectStore(tmp_path)
    cli.cmd_enable(store, 'https://example.com', 'daily')
    out = cli.cmd_disable(store, 'https://example.com')
    assert out['disabled'] is True
    assert store.get('example.com').get_monitor()['enabled'] is False


def test_cmd_disable_unknown_project(tmp_path):
    store = ProjectStore(tmp_path)
    assert 'error' in cli.cmd_disable(store, 'https://nope.com')


def test_cmd_status_lists_only_monitored(tmp_path):
    store = ProjectStore(tmp_path)
    cli.cmd_enable(store, 'https://watched.com', 'daily')
    store.get_or_create('https://unwatched.com')   # no schedule
    rows = cli.cmd_status(store)
    assert [r['slug'] for r in rows] == ['watched.com']
    assert rows[0]['enabled'] is True


def test_cmd_run_executes_due(tmp_path, monkeypatch):
    store = ProjectStore(tmp_path)
    project = store.get_or_create('https://x.com')
    # Due now: next_run in the past.
    project.set_monitor({'enabled': True, 'interval': 'daily',
                         'next_run': '2000-01-01T00:00:00'})

    # Inject an offline collection step (no real CollectionRunner / network).
    # run_due now builds the run_fn per project from its options, so the patch
    # target is _build_run_fn(base, options).
    def fake_build(base, options=None):
        def run(url):
            sid = '20260613_120000'
            proj = store.get(project_slug(url))
            sd = proj.start_scan(sid)
            report = {'url': url, 'status': 'Success', 'scan_id': sid,
                      'executive_summary': {'risk_level': 'Low'}}
            (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
            proj.record_scan(sd, report)
            return report
        return run

    monkeypatch.setattr(cli.monitor, '_build_run_fn', fake_build)
    results = cli.cmd_run(store)
    assert len(results) == 1 and results[0]['slug'] == 'x.com'
    # schedule advanced past the epoch placeholder
    assert store.get('x.com').get_monitor()['last_scan_id'] == '20260613_120000'


def test_cmd_run_missions_executes_due():
    from core import mission_schedule as ms, pentest_mission as pm
    from core.mission_store import MissionStore
    mission = pm.advance_mission_status(
        pm.create_mission('shop.com', 'review', allowed_actions=['headers_check']),
        'ready')
    saved = MissionStore().save_mission(mission)
    ms.set_mission_schedule(saved['id'], 'daily')
    store = MissionStore()
    store.set_schedule(saved['id'], {**store.get_schedule(saved['id']),
                                     'next_run': '2000-01-01T00:00:00'})

    results = cli.cmd_run_missions()
    assert [r['mission_id'] for r in results] == [saved['id']]
    assert results[0]['status'] == 'ok'


def _ci_scan(project, sid, subdomains):
    """Record a scan whose subdomains phase carries ``subdomains`` (a takeover
    candidate there produces a critical diff event the CI gate catches)."""
    sd = project.start_scan(sid)
    report = {'url': 'https://t.com', 'status': 'Success', 'scan_id': sid,
              'executive_summary': {'risk_level': 'Low', 'risk_100': 0},
              'phases': {'subdomains': {'status': 'Success',
                                        'data': {'results': subdomains}}}}
    (sd / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(sd, report)
    return report


def test_cmd_ci_single_scan_passes(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.get_or_create('https://t.com')
    _ci_scan(project, '20260101_000000', [{'subdomain': 'a.t.com'}])
    out = cli.cmd_ci(store, 'https://t.com', tmp_path, scan=False)
    assert out['baseline'] is None and out['current'] == '20260101_000000'
    assert out['gate']['fail'] is False


def test_cmd_ci_new_takeover_fails(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.get_or_create('https://t.com')
    _ci_scan(project, '20260101_000000', [{'subdomain': 'a.t.com'}])
    _ci_scan(project, '20260102_000000',
             [{'subdomain': 'a.t.com'},
              {'subdomain': 'gone.t.com', 'takeover': True}])
    out = cli.cmd_ci(store, 'https://t.com', tmp_path, fail_on='high', scan=False)
    assert out['baseline'] == '20260101_000000'
    assert out['current'] == '20260102_000000'
    assert out['gate']['fail'] is True
    assert 'critical' in out['gate']['counts']   # takeover → critical ≥ high


def test_cmd_ci_scan_invokes_run_fn(tmp_path):
    store = ProjectStore(tmp_path)
    calls = []

    def fake_run(url, base):
        calls.append((url, base))
        _ci_scan(store.get_or_create(url), '20260103_000000',
                 [{'subdomain': 'a.t.com'}])

    out = cli.cmd_ci(store, 'https://t.com', tmp_path, scan=True, run_fn=fake_run)
    assert calls and calls[0][0] == 'https://t.com'
    assert out['current'] == '20260103_000000' and out['gate']['fail'] is False


def test_cmd_ci_writes_sarif(tmp_path):
    store = ProjectStore(tmp_path)
    project = store.get_or_create('https://t.com')
    _ci_scan(project, '20260101_000000', [{'subdomain': 'a.t.com'}])
    sarif = tmp_path / 'out.sarif'
    out = cli.cmd_ci(store, 'https://t.com', tmp_path, scan=False,
                     sarif_out=str(sarif))
    assert out['sarif_out'] == str(sarif) and sarif.exists()
    assert json.loads(sarif.read_text(encoding='utf-8'))['version'] == '2.1.0'


def test_cmd_issues_creates_via_injected_client(tmp_path):
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    fstore = FindingsStore(tmp_path / 'f.db')
    f = {'id': fingerprint('vuln', 'sqli', 'https://t.com/a'), 'category': 'vuln',
         'rule_id': 'sqli', 'title': 'SQLi', 'severity': 'high',
         'evidence': {'location': 'https://t.com/a'}}
    fstore.upsert('t.com', f)               # project slug of https://t.com
    store = ProjectStore(tmp_path)

    class _Client:
        def create_issue(self, title, body, labels=None):
            return {'number': 1, 'url': 'https://gh/issues/1'}

    cfg = {'enabled': True, 'token': 't', 'owner': 'o', 'repo': 'r'}
    out = cli.cmd_issues(store, 'https://t.com', config=cfg,
                         findings_store=fstore, client=_Client())
    assert len(out['created']) == 1 and out['created'][0]['number'] == 1
    assert out['skipped'] == 0


def test_cmd_compliance_writes_report(tmp_path):
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    fstore = FindingsStore(tmp_path / 'f.db')
    fstore.upsert('t.com', {'id': fingerprint('vuln', 'sqli', 'https://t.com/s'),
                            'category': 'vuln', 'rule_id': 'sqli',
                            'title': 'SQLi', 'severity': 'high',
                            'evidence': {'location': 'https://t.com/s'}})
    store = ProjectStore(tmp_path)
    out_path = tmp_path / 'compliance.md'
    out = cli.cmd_compliance(store, 'https://t.com', out=str(out_path),
                             findings_store=fstore)
    assert out['out'] == str(out_path) and out_path.exists()
    assert out['summary']['total_findings'] == 1
    assert 'A03:2021 Injection' in out_path.read_text(encoding='utf-8')


def test_main_enable_then_status(tmp_path, capsys):
    base = str(tmp_path)
    cli.main(['--output', base, 'enable', 'https://example.com',
              '--interval', 'monthly'])
    cli.main(['--output', base, 'status'])
    out = capsys.readouterr().out
    assert 'example.com' in out and 'monthly' in out


def test_main_default_output_uses_settings(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'load_settings',
                        lambda: {'output_dir': str(tmp_path)})
    cli.main(['enable', 'https://settings.example', '--interval', 'daily'])
    cli.main(['status'])
    out = capsys.readouterr().out
    assert 'settings.example' in out
    assert (tmp_path / 'Projects' / 'settings.example' / 'metadata.json').exists()
