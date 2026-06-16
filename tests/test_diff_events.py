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


def test_graphql_new_endpoint_and_introspection_open():
    d = _diff(
        graphql={
            'added': ['https://x.com/graphql: reachable',
                      'https://x.com/api/graphql: introspection on'],
            'removed': [],
            # an endpoint whose schema flipped open between scans
            'changed': [{'key': 'https://x.com/v2/graphql',
                         'a': 'reachable', 'b': 'introspection on'}],
        })
    by_type = {}
    for e in diff_events(d):
        by_type.setdefault(e['type'], []).append(e)
    # a plain reachable endpoint is surface discovery (medium, timeline-only)
    assert by_type['new_graphql'][0]['severity'] == 'medium'
    # an added-already-open endpoint AND a reachable→open transition both fire high
    intro = by_type['graphql_introspection']
    assert len(intro) == 2
    assert all(e['severity'] == 'high' for e in intro)
    assert any('→ introspection on' in e['title'] for e in intro)


def test_graphql_introspection_is_alertable_but_new_graphql_is_not():
    d = _diff(graphql={
        'added': ['https://x.com/graphql: reachable',
                  'https://x.com/g: introspection on'],
        'removed': [], 'changed': []})
    alert_types = {a['type'] for a in alerts.extract_alerts(d)}
    assert 'graphql_introspection' in alert_types     # high signal → alertable
    assert 'new_graphql' not in alert_types           # surface discovery only


def test_certificate_expiry_classified_from_status_field():
    d = _diff(certificates={
        'added': ['expiry: expiring', 'subject: x.com'],   # newly-tracked, near deadline
        'removed': [],
        # a cert that crossed its deadline between scans; not_after change is generic
        'changed': [{'key': 'expiry', 'a': 'valid', 'b': 'expired'},
                    {'key': 'not_after', 'a': 'Aug 1', 'b': 'Sep 1'}]})
    by_type = {}
    for e in diff_events(d):
        by_type.setdefault(e['type'], []).append(e)
    assert by_type['cert_expiring'][0]['severity'] == 'medium'   # added near-deadline
    assert by_type['cert_expired'][0]['severity'] == 'high'      # valid→expired
    assert '→ expired' in by_type['cert_expired'][0]['title']
    assert by_type['cert_change'][0]['title'].startswith('not_after:')  # generic field


def test_certificate_renewal_emits_no_expiry_event():
    # expired/expiring → valid (renewed) is not an expiry regression.
    d = _diff(certificates=_changed({'key': 'expiry', 'a': 'expired', 'b': 'valid'}))
    types = {e['type'] for e in diff_events(d)}
    assert 'cert_expired' not in types and 'cert_expiring' not in types


def test_cert_expired_is_alertable_but_expiring_is_not():
    d = _diff(certificates={
        'added': ['expiry: expiring'],
        'removed': [],
        'changed': [{'key': 'expiry', 'a': 'valid', 'b': 'expired'}]})
    alert_types = {a['type'] for a in alerts.extract_alerts(d)}
    assert 'cert_expired' in alert_types        # crossed the deadline → alertable
    assert 'cert_expiring' not in alert_types   # heads-up only → timeline


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
