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
    def fake_default(base):
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

    monkeypatch.setattr(cli.monitor, '_default_run_fn', fake_default)
    results = cli.cmd_run(store)
    assert len(results) == 1 and results[0]['slug'] == 'x.com'
    # schedule advanced past the epoch placeholder
    assert store.get('x.com').get_monitor()['last_scan_id'] == '20260613_120000'


def test_main_enable_then_status(tmp_path, capsys):
    base = str(tmp_path)
    cli.main(['--output', base, 'enable', 'https://example.com',
              '--interval', 'monthly'])
    cli.main(['--output', base, 'status'])
    out = capsys.readouterr().out
    assert 'example.com' in out and 'monthly' in out
