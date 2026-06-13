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
    }
    names = {c.name for c in alerts.build_channels(cfg)}
    assert names == {'telegram', 'discord', 'email'}


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
