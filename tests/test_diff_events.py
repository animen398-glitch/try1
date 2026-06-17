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


def test_placeholder_secret_is_not_an_event():
    # A secret the diff tagged ⚠ placeholder (offline-validated false positive) is
    # neither alertable nor a timeline event; a plain secret still is.
    d = _diff(secrets=_added('aws: AKIA…(20)',
                             'generic: your…(17) ⚠ placeholder'))
    secret_events = [e for e in diff_events(d) if e['type'] == 'new_secret']
    assert len(secret_events) == 1
    assert 'placeholder' not in secret_events[0]['title']


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


def test_sourcemap_leak_classified_and_alertable():
    d = _diff(sourcemap=_added('https://x.com/app.js.map'))
    events = diff_events(d)
    smap = [e for e in events if e['type'] == 'new_sourcemap']
    assert len(smap) == 1
    assert smap[0]['severity'] == 'high' and smap[0]['section'] == 'sourcemap'
    # A newly-leaking source map is a regression worth a push (like an opened
    # GraphQL schema).
    assert 'new_sourcemap' in {a['type'] for a in alerts.extract_alerts(d)}


def test_cookie_weakened_is_alertable_but_new_weak_cookie_is_not():
    d = _diff(cookies={
        'added': ['tracker: Weak', 'csrf: Strong'],   # newly-served cookies
        'removed': [],
        # an existing cookie that lost protection between scans
        'changed': [{'key': 'sid', 'a': 'Strong', 'b': 'Weak'}]})
    by_type = {}
    for e in diff_events(d):
        by_type.setdefault(e['type'], []).append(e)
    # a brand-new weak cookie is surface discovery (medium, timeline-only); a
    # new Strong cookie is not an event at all
    assert len(by_type['weak_cookie']) == 1
    assert by_type['weak_cookie'][0]['severity'] == 'medium'
    # a cookie that degraded to Weak is a regression worth a push
    assert by_type['cookie_weakened'][0]['severity'] == 'high'
    assert '→ Weak' in by_type['cookie_weakened'][0]['title']
    alert_types = {a['type'] for a in alerts.extract_alerts(d)}
    assert 'cookie_weakened' in alert_types        # regression → alertable
    assert 'weak_cookie' not in alert_types        # discovery only


def test_vulnerable_dependency_classified_and_alertable():
    d = _diff(dependencies={
        # a vulnerable library that newly appears, plus a clean one (no event)
        'added': ['jquery 1.7 ⚠ vulnerable', 'lodash 4.17.21'],
        'removed': [],
        # an existing library that turned vulnerable, plus a benign version bump
        'changed': [{'key': 'axios', 'a': '0.21', 'b': '0.21 ⚠'},
                    {'key': 'react', 'a': '17', 'b': '18'}]})
    by_type = {}
    for e in diff_events(d):
        by_type.setdefault(e['type'], []).append(e)
    # only the vulnerable newcomer is an event (the clean lib is not)
    assert len(by_type['new_vulnerable_dependency']) == 1
    assert by_type['new_vulnerable_dependency'][0]['severity'] == 'high'
    assert by_type['new_vulnerable_dependency'][0]['section'] == 'dependencies'
    # only the safe→vulnerable transition is an event (the benign bump is not)
    assert len(by_type['dependency_vulnerable']) == 1
    assert by_type['dependency_vulnerable'][0]['severity'] == 'high'
    assert by_type['dependency_vulnerable'][0]['title'].startswith('axios:')
    # both are clear new risk → alertable (like a newly-leaking source map)
    alert_types = {a['type'] for a in alerts.extract_alerts(d)}
    assert 'new_vulnerable_dependency' in alert_types
    assert 'dependency_vulnerable' in alert_types


def test_security_header_removed_classified_and_alertable():
    d = _diff(headers={
        # HSTS dropped (regression); Server header changed (not a security header)
        'added': [],
        'removed': ['strict-transport-security: max-age=31536000',
                    'X-Cache: HIT'],   # non-security removal → no event
        'changed': [{'key': 'Server', 'a': 'nginx', 'b': 'cloudflare'}]})
    by_type = {}
    for e in diff_events(d):
        by_type.setdefault(e['type'], []).append(e)
    # only the dropped security header is an event (the X-Cache removal is not)
    assert len(by_type['security_header_removed']) == 1
    assert by_type['security_header_removed'][0]['severity'] == 'high'
    assert by_type['security_header_removed'][0]['section'] == 'headers'
    # a dropped protection is a regression worth a push
    assert 'security_header_removed' in {a['type'] for a in alerts.extract_alerts(d)}


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


def test_new_historical_url_is_timeline_only():
    # A newly-surfaced interesting archived URL is a medium discovery note, but
    # not alertable (archival presence is discovery, not a live regression).
    d = _diff(historical=_added('https://x.com/admin/login'))
    events = diff_events(d)
    assert [e['type'] for e in events] == ['new_historical_url']
    assert events[0]['severity'] == 'medium'
    assert events[0]['section'] == 'historical'
    assert alerts.extract_alerts(d) == []
    assert 'new_historical_url' not in alerts.ALERT_TYPES


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
