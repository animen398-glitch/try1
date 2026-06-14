"""Shared change-event classifier (core/scan_diff.diff_events, F2 T2.1).

diff_events is the single source of truth that both Alert Center and the Timeline
consume. These tests pin its classification and verify the Alert Center wrapper
(alerts.extract_alerts) is exactly the alertable subset — no behaviour drift.
Pure, offline.
"""

from core import alerts
from core.scan_diff import diff_events


def _diff(risk=None, **sections):
    return {'risk': risk or {'level_a': 'Low', 'level_b': 'Low',
                             'risk_100_a': 10, 'risk_100_b': 10},
            'sections': sections}


def _added(*items):
    return {'added': list(items), 'removed': [], 'changed': []}


def _changed(*items):
    return {'added': [], 'removed': [], 'changed': list(items)}


# ── classification ─────────────────────────────────────────────────────────────

def test_classifies_each_section():
    d = _diff(
        secrets=_added('aws: AKIA****'),
        subdomains=_added('api.x.com', 'old.x.com ⚠ takeover'),
        technologies={'added': ['React 18'], 'removed': [],
                      'changed': [{'key': 'React', 'a': '17', 'b': '18'}]},
        certificates=_changed({'key': 'not_after', 'a': '2026', 'b': '2027'}),
        endpoints=_added('https://x.com/api/v1/u'),
        apis=_added('GET /v2/items'),
        risk={'level_a': 'Low', 'level_b': 'High',
              'risk_100_a': 10, 'risk_100_b': 60},
    )
    by_type = {}
    for e in diff_events(d):
        by_type.setdefault(e['type'], []).append(e)

    assert by_type['new_secret'][0]['severity'] == 'high'
    assert by_type['new_subdomain'][0]['title'] == 'api.x.com'
    assert by_type['takeover'][0]['severity'] == 'critical'
    assert 'new_technology' in by_type
    assert by_type['tech_version_change'][0]['title'].startswith('React:')
    assert by_type['cert_change'][0]['severity'] == 'medium'
    # endpoints + apis both fold into new_endpoint
    assert len(by_type['new_endpoint']) == 2
    assert by_type['risk_increase'][0]['severity'] == 'high'


def test_risk_decrease_is_emitted():
    d = _diff(risk={'level_a': 'High', 'level_b': 'Low',
                    'risk_100_a': 60, 'risk_100_b': 10})
    types = [e['type'] for e in diff_events(d)]
    assert types == ['risk_decrease']


def test_no_risk_event_when_unchanged():
    assert diff_events(_diff()) == []


def test_empty_and_none_safe():
    assert diff_events({}) == []
    assert diff_events(None) == []


def test_every_event_carries_section():
    d = _diff(secrets=_added('k'))
    assert all('section' in e for e in diff_events(d))


# ── Alert Center is exactly the alertable subset ───────────────────────────────

def test_extract_alerts_is_alertable_subset_of_diff_events():
    d = _diff(
        secrets=_added('aws: AKIA****'),
        endpoints=_added('https://x.com/api'),     # timeline-only → not an alert
        technologies={'added': [], 'removed': [],
                      'changed': [{'key': 'React', 'a': '17', 'b': '18'}]},  # ditto
        risk={'level_a': 'Low', 'level_b': 'High',
              'risk_100_a': 10, 'risk_100_b': 60},
    )
    alert_types = {a['type'] for a in alerts.extract_alerts(d)}
    assert alert_types == {'new_secret', 'risk_increase'}
    # timeline-only types never leak into alerts
    assert 'new_endpoint' not in alert_types
    assert 'tech_version_change' not in alert_types
    # alert events keep the lean {type,title,severity} shape (no section key)
    for a in alerts.extract_alerts(d):
        assert set(a) == {'type', 'title', 'severity'}
