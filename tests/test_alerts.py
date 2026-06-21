"""Tests for Alert Center (core/alerts.py, roadmap Phase 9).

Pure alert extraction is tested directly; channel dispatch is tested with the
module-level transport (_http_post / _smtp_send) stubbed, so nothing hits the
network.
"""

from core import alerts


# ── a representative Scan Diff dict ───────────────────────────────────────────

def _diff(**sections):
    base = {
        'risk': {'level_a': 'Low', 'level_b': 'Low',
                 'risk_100_a': 10, 'risk_100_b': 10},
        'sections': sections,
    }
    return base


# ── extract_alerts (pure) ─────────────────────────────────────────────────────

def test_extract_new_secret_and_technology():
    d = _diff(secrets={'added': ['aws: AKIA****', 'stripe: sk_****'],
                       'removed': [], 'changed': []},
              technologies={'added': ['React 18'], 'removed': [], 'changed': []})
    out = alerts.extract_alerts(d)
    kinds = [a['type'] for a in out]
    assert kinds.count('new_secret') == 2
    assert 'new_technology' in kinds
    # masked secret text flows straight through
    assert any('AKIA****' in a['title'] for a in out)


def test_subdomain_splits_takeover_from_plain():
    d = _diff(subdomains={'added': ['api.x.com', 'old.x.com ⚠ takeover'],
                          'removed': [], 'changed': []})
    out = alerts.extract_alerts(d)
    by = {a['type']: a for a in out}
    assert 'new_subdomain' in by and by['new_subdomain']['title'] == 'api.x.com'
    assert 'takeover' in by and by['takeover']['severity'] == 'critical'


def test_cert_change_and_risk_increase():
    d = {
        'risk': {'level_a': 'Low', 'level_b': 'High',
                 'risk_100_a': 10, 'risk_100_b': 60},
        'sections': {'certificates': {'added': [], 'removed': [], 'changed': [
            {'key': 'not_after', 'a': '2026', 'b': '2027'}]}},
    }
    out = alerts.extract_alerts(d)
    kinds = [a['type'] for a in out]
    assert 'cert_change' in kinds and 'risk_increase' in kinds


def test_no_risk_alert_when_score_not_increasing():
    d = _diff()
    d['risk'] = {'level_a': 'High', 'level_b': 'Low',
                 'risk_100_a': 60, 'risk_100_b': 10}
    assert alerts.extract_alerts(d) == []


def test_types_filter():
    d = _diff(secrets={'added': ['k'], 'removed': [], 'changed': []},
              technologies={'added': ['React'], 'removed': [], 'changed': []})
    out = alerts.extract_alerts(d, types=['new_secret'])
    assert [a['type'] for a in out] == ['new_secret']


def test_extract_empty_diff_is_safe():
    assert alerts.extract_alerts({}) == []
    assert alerts.extract_alerts(None) == []


# ── channels / build_channels ─────────────────────────────────────────────────

def test_build_channels_by_present_fields():
    cfg = {
        'telegram': {'token': 't', 'chat_id': 'c'},
        'discord': {'webhook_url': 'https://d'},
        'email': {'host': 'h', 'from': 'a@b', 'to': 'c@d'},
        'webhook': {'url': 'https://hook'},
    }
    names = {c.name for c in alerts.build_channels(cfg)}
    assert names == {'telegram', 'discord', 'email', 'webhook'}


def test_build_channels_skips_webhook_without_url():
    assert all(c.name != 'webhook'
               for c in alerts.build_channels({'webhook': {}}))


def test_webhook_channel_posts_json_envelope(monkeypatch):
    import json as _json
    captured = {}

    def _fake(url, data, headers, timeout=10.0):
        captured['url'] = url
        captured['payload'] = _json.loads(data.decode('utf-8'))
        captured['ctype'] = headers.get('Content-Type')
        return 202   # a 2xx that is neither 200 nor 204

    monkeypatch.setattr(alerts, '_http_post', _fake)
    res = alerts.WebhookChannel('https://hook').send('Subj', 'Body')
    assert res == {'channel': 'webhook', 'status': 'ok'}      # any 2xx is ok
    assert captured['url'] == 'https://hook'
    assert captured['ctype'] == 'application/json'
    assert captured['payload'] == {'text': 'Subj\n\nBody',
                                   'subject': 'Subj', 'body': 'Body'}


def test_webhook_channel_non_2xx_status(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 500)
    assert 'http 500' in alerts.WebhookChannel('https://hook').send('s', 'b')['status']


def test_build_channels_skips_incomplete():
    cfg = {'telegram': {'token': 't'},          # missing chat_id
           'discord': {},                        # missing webhook
           'email': {'host': 'h'}}               # missing from/to
    assert alerts.build_channels(cfg) == []


def test_telegram_and_discord_status_mapping(monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, '_http_post',
                        lambda url, data, headers, timeout=10.0:
                        (calls.append((url, data)), 200)[1])
    assert alerts.TelegramChannel('t', 'c').send('s', 'b')['status'] == 'ok'
    # Discord success is 204
    monkeypatch.setattr(alerts, '_http_post',
                        lambda *a, **k: 204)
    assert alerts.DiscordChannel('https://d').send('s', 'b')['status'] == 'ok'
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 500)
    assert 'http 500' in alerts.DiscordChannel('https://d').send('s', 'b')['status']
    assert calls and 'api.telegram.org' in calls[0][0]


def test_email_channel_uses_smtp(monkeypatch):
    seen = {}
    monkeypatch.setattr(alerts, '_smtp_send',
                        lambda cfg, subject, body, timeout=15.0:
                        seen.update(cfg=cfg, subject=subject))
    cfg = {'host': 'h', 'from': 'a@b', 'to': 'c@d'}
    assert alerts.EmailChannel(cfg).send('subj', 'body')['status'] == 'ok'
    assert seen['subject'] == 'subj'


def test_dispatch_is_graceful_on_channel_error(monkeypatch):
    class Boom:
        name = 'boom'

        def send(self, s, b):
            raise RuntimeError('down')

    results = alerts.dispatch([Boom()], 's', 'b')
    assert results[0]['status'] == 'error' and 'down' in results[0]['error']


# ── notify (top-level) ────────────────────────────────────────────────────────

def test_notify_disabled_is_noop():
    out = alerts.notify({'enabled': False}, 'x.com', _diff(
        secrets={'added': ['k'], 'removed': [], 'changed': []}))
    assert out == {'alerts': 0, 'sent': 0, 'reason': 'disabled'}


def test_notify_no_channels_reports_reason():
    cfg = {'enabled': True}
    out = alerts.notify(cfg, 'x.com',
                        _diff(secrets={'added': ['k'], 'removed': [], 'changed': []}))
    assert out['alerts'] == 1 and out['sent'] == 0 and out['reason'] == 'no channels'


def test_notify_sends_over_channels(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    cfg = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}
    out = alerts.notify(cfg, 'x.com',
                        _diff(secrets={'added': ['aws: AKIA****'],
                                       'removed': [], 'changed': []}))
    assert out['alerts'] == 1 and out['sent'] == 1
    assert 'x.com' in out['subject']


def test_send_test(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    out = alerts.send_test({'discord': {'webhook_url': 'https://d'}})
    assert out['sent'] == 1
    assert alerts.send_test({})['sent'] == 0


# ── SLA-breach alert channel (time-triggered, one-shot via the findings store) ──

def _finding_dict(severity='high'):
    from core.finding_fingerprint import fingerprint
    return {'id': fingerprint('vuln', 'https', 'https://x.com/'),
            'category': 'vuln', 'rule_id': 'https', 'title': 'Plain HTTP',
            'severity': severity, 'evidence': None}


def _findings_store(tmp_path, *, first_seen):
    from core.findings_store import FindingsStore
    s = FindingsStore(tmp_path / 'findings.db')
    s.upsert('proj', _finding_dict(), now=first_seen)
    return s


def test_collect_sla_alerts_new_breach_then_deduped(tmp_path):
    # first_seen far past the high (30d) SLA window → breached now.
    s = _findings_store(tmp_path, first_seen='2020-01-01T00:00:00')
    first = alerts.collect_sla_alerts(s, 'proj')
    assert len(first) == 1
    assert first[0]['type'] == 'sla_breach' and first[0]['severity'] == 'high'
    assert 'SLA' in first[0]['title']
    # Second run: still breached but already alerted → nothing new.
    assert alerts.collect_sla_alerts(s, 'proj') == []


def test_collect_sla_alerts_empty_when_within_window(tmp_path):
    from datetime import datetime
    s = _findings_store(tmp_path,
                        first_seen=datetime.now().isoformat(timespec='seconds'))
    assert alerts.collect_sla_alerts(s, 'proj') == []


def test_notify_sla_dispatches_and_honors_types_filter(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    events = [{'type': 'sla_breach', 'title': '[high] Plain HTTP — SLA просрочено',
               'severity': 'high'}]
    cfg = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}
    out = alerts.notify_sla(cfg, 'x.com', events)
    assert out['alerts'] == 1 and out['sent'] == 1
    # A types filter that omits sla_breach suppresses it.
    cfg_filtered = {**cfg, 'types': ['new_secret']}
    assert alerts.notify_sla(cfg_filtered, 'x.com', events)['alerts'] == 0


def test_notify_sla_disabled_is_noop():
    out = alerts.notify_sla({'enabled': False}, 'x.com',
                            [{'type': 'sla_breach', 'title': 't', 'severity': 'high'}])
    assert out == {'alerts': 0, 'sent': 0, 'reason': 'disabled'}


# ── audit-only-secret alert channel (finding-triggered, one-shot via the store) ──

def _secret_finding_dict(stype='AWS Access Key', source='secret-audit',
                         location='https://x.com/app.js', evidence=None):
    from core.finding_fingerprint import fingerprint
    return {'id': fingerprint('secret', stype, location),
            'category': 'secret', 'rule_id': '',
            'title': f'Leaked secret: {stype}', 'severity': 'high',
            'evidence': evidence if evidence is not None
            else {'source': source, 'location': location}}


def _secret_store(db_path, *findings):
    from core.findings_store import FindingsStore
    s = FindingsStore(db_path)
    for f in findings:
        s.upsert('proj', f)
    return s


def test_collect_secret_alerts_audit_only_then_deduped(tmp_path):
    s = _secret_store(tmp_path / 'findings.db', _secret_finding_dict())
    first = alerts.collect_secret_alerts(s, 'proj')
    assert len(first) == 1
    assert first[0]['type'] == 'new_secret' and first[0]['severity'] == 'high'
    assert 'AWS Access Key' in first[0]['title']
    # Second run: already alerted → nothing new (one-shot via the store marker).
    assert alerts.collect_secret_alerts(s, 'proj') == []


def test_collect_secret_alerts_skips_diff_covered_api_secret(tmp_path):
    # An api-phase secret (source 'secret') is covered by the Scan Diff's new_secret,
    # so the finding-based channel must NOT double-alert it — even when merged with an
    # audit source.
    s = _secret_store(tmp_path / 'a.db', _secret_finding_dict(source='secret'))
    assert alerts.collect_secret_alerts(s, 'proj') == []
    both = _secret_finding_dict(evidence={'sources': ['secret', 'secret-audit']})
    s2 = _secret_store(tmp_path / 'b.db', both)
    assert alerts.collect_secret_alerts(s2, 'proj') == []


def test_collect_secret_alerts_document_only_secret(tmp_path):
    # A secret found only by Document Intelligence (source 'document') has no Scan
    # Diff representation either (the diff's secrets section reads only the api
    # phase), so the finding-based channel must alert it — same gap as 'secret-audit'.
    s = _secret_store(tmp_path / 'doc.db',
                      _secret_finding_dict(source='document',
                                           location='https://x.com/leak.pdf'))
    out = alerts.collect_secret_alerts(s, 'proj')
    assert len(out) == 1
    assert out[0]['type'] == 'new_secret' and 'AWS Access Key' in out[0]['title']
    # One-shot: a second run yields nothing new.
    assert alerts.collect_secret_alerts(s, 'proj') == []


def test_collect_secret_alerts_tiers_generic(tmp_path):
    # A generic/opaque key tiers down to new_secret_generic (medium), like the diff.
    s = _secret_store(tmp_path / 'g.db', _secret_finding_dict(stype='Generic API Key'))
    out = alerts.collect_secret_alerts(s, 'proj')
    assert len(out) == 1
    assert out[0]['type'] == 'new_secret_generic' and out[0]['severity'] == 'medium'


def test_notify_secret_dispatches_and_honors_types_filter(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    events = [{'type': 'new_secret', 'title': 'Leaked secret: AWS Access Key',
               'severity': 'high'}]
    cfg = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}
    out = alerts.notify_secret(cfg, 'x.com', events)
    assert out['alerts'] == 1 and out['sent'] == 1
    # A types filter that omits new_secret suppresses it.
    cfg_filtered = {**cfg, 'types': ['sla_breach']}
    assert alerts.notify_secret(cfg_filtered, 'x.com', events)['alerts'] == 0


def test_notify_secret_disabled_is_noop():
    out = alerts.notify_secret({'enabled': False}, 'x.com',
                               [{'type': 'new_secret', 'title': 't', 'severity': 'high'}])
    assert out == {'alerts': 0, 'sent': 0, 'reason': 'disabled'}


# ── generic high/critical-finding alert channel (finding-triggered, one-shot) ───

def _vuln_finding_dict(title='SQL Injection', severity='High', source='nuclei',
                       rule_id='sqli', location='https://x.com/q', evidence=None):
    from core.finding_fingerprint import fingerprint
    return {'id': fingerprint('vuln', rule_id, location),
            'category': 'vuln', 'rule_id': rule_id, 'title': title,
            'severity': severity,
            'evidence': evidence if evidence is not None
            else {'source': source, 'location': location}}


def test_collect_finding_alerts_high_then_deduped(tmp_path):
    s = _secret_store(tmp_path / 'f.db', _vuln_finding_dict())
    first = alerts.collect_finding_alerts(s, 'proj')
    assert len(first) == 1
    assert first[0]['type'] == 'new_finding' and first[0]['severity'] == 'high'
    assert 'SQL Injection' in first[0]['title'] and '[High]' in first[0]['title']
    # Second run: already alerted → nothing new (one-shot via the store marker).
    assert alerts.collect_finding_alerts(s, 'proj') == []


def test_collect_finding_alerts_skips_low_and_dedicated_categories(tmp_path):
    # Medium/low severity is below the bar; dependency-audit CVEs and the categories
    # with a dedicated alert (secret here) are excluded to avoid a double alert.
    s = _secret_store(
        tmp_path / 'g.db',
        _vuln_finding_dict(title='Verbose error', severity='Medium', rule_id='err'),
        _vuln_finding_dict(title='Vuln lib', severity='High', rule_id='cve-1',
                           source='dependency-audit'),
        _secret_finding_dict(),   # category 'secret' → its own channel, not here
    )
    assert alerts.collect_finding_alerts(s, 'proj') == []


def test_notify_findings_dispatches_and_honors_types_filter(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    events = [{'type': 'new_finding', 'title': '[High] SQL Injection',
               'severity': 'high'}]
    cfg = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}
    out = alerts.notify_findings(cfg, 'x.com', events)
    assert out['alerts'] == 1 and out['sent'] == 1
    cfg_filtered = {**cfg, 'types': ['sla_breach']}
    assert alerts.notify_findings(cfg_filtered, 'x.com', events)['alerts'] == 0


def test_notify_findings_disabled_is_noop():
    out = alerts.notify_findings({'enabled': False}, 'x.com',
                                 [{'type': 'new_finding', 'title': 't', 'severity': 'high'}])
    assert out == {'alerts': 0, 'sent': 0, 'reason': 'disabled'}


# ── delivery journal (F4 — reuses OperationRegistry; ops DB isolated by conftest) ─

def _alert_ops():
    from utils.operation_registry import OperationRegistry
    return OperationRegistry().history(phase='alert')


def test_notify_records_delivery_to_journal(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    cfg = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}
    alerts.notify(cfg, 'x.com', _diff(
        secrets={'added': ['aws: AKIA****'], 'removed': [], 'changed': []}))
    ops = _alert_ops()
    assert len(ops) == 1
    op = ops[0]
    assert op['target'] == 'x.com' and op['phase'] == 'alert'
    assert op['status'] == 'success'
    assert op['metadata']['kind'] == 'notify' and op['metadata']['sent'] == 1


def test_send_test_records_delivery(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 200)
    alerts.send_test({'discord': {'webhook_url': 'https://d'}})
    ops = _alert_ops()
    assert len(ops) == 1 and ops[0]['target'] == 'alert-test'
    assert ops[0]['metadata']['kind'] == 'test'


def test_noop_dispatch_is_not_journaled():
    # disabled / no-channels never reach dispatch → nothing is journaled.
    d = _diff(secrets={'added': ['k'], 'removed': [], 'changed': []})
    alerts.notify({'enabled': False}, 'x.com', d)
    alerts.notify({'enabled': True}, 'x.com', d)      # no channels configured
    assert _alert_ops() == []


def test_failed_channel_marks_journal_failed(monkeypatch):
    monkeypatch.setattr(alerts, '_http_post', lambda *a, **k: 500)
    cfg = {'enabled': True, 'telegram': {'token': 't', 'chat_id': 'c'}}
    alerts.notify(cfg, 'x.com', _diff(
        secrets={'added': ['k'], 'removed': [], 'changed': []}))
    assert _alert_ops()[0]['status'] == 'failed'
