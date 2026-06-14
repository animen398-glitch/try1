"""Tests for the findings SQLite store (core/findings_store.py, F1 T1.2).

Persistence layer only: schema/migration idempotency, upsert (CREATE vs SEEN),
status transitions + event log, queries/summary. Each test uses an isolated
tmp DB; no network.
"""

import sqlite3

import pytest

from core.finding_fingerprint import fingerprint, scoped_id
from core.findings_store import FindingsStore


def _store(tmp_path):
    return FindingsStore(tmp_path / 'findings.db')


def _finding(title='Plain HTTP', category='vuln', rule_id='https', severity='high',
             location='https://x.com/', evidence=None):
    return {'id': fingerprint(category, rule_id, location),
            'category': category, 'rule_id': rule_id, 'title': title,
            'severity': severity, 'evidence': evidence}


def _sid(project, finding):
    """The project-scoped storage id of a finding — the key the store uses for
    get/set_status/events (the input ``finding['id']`` is the bare fingerprint)."""
    return scoped_id(project, finding['id'])


# ── schema / migration idempotency ────────────────────────────────────────────

def test_schema_is_idempotent_and_versioned(tmp_path):
    db = tmp_path / 'findings.db'
    s1 = _store(tmp_path)
    s1.upsert('proj', _finding())
    # Re-opening the same DB must not error or wipe data (CREATE IF NOT EXISTS).
    s2 = FindingsStore(db)
    assert len(s2.list_findings('proj')) == 1
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2


# ── upsert: CREATE vs SEEN ────────────────────────────────────────────────────

def test_upsert_creates_then_sees(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    r1 = s.upsert('proj', f, scan_id='s1')
    assert r1['created'] is True
    assert r1['finding']['status'] == 'OPEN'
    assert r1['finding']['status_source'] == 'auto'
    first_seen = r1['finding']['first_seen_at']

    r2 = s.upsert('proj', {**f, 'title': 'Plain HTTP (still)'}, scan_id='s2',
                  now='2099-01-01T00:00:00')
    assert r2['created'] is False
    assert r2['finding']['title'] == 'Plain HTTP (still)'      # refreshed
    assert r2['finding']['first_seen_at'] == first_seen        # not reset
    assert r2['finding']['last_seen_at'] == '2099-01-01T00:00:00'

    types = [e['type'] for e in s.events(_sid('proj', f))]
    assert types == ['CREATED', 'SEEN']


def test_upsert_stores_evidence_as_json(tmp_path):
    s = _store(tmp_path)
    f = _finding(evidence={'location': 'https://x.com/a.js', 'masked': 'AKIA…20'})
    s.upsert('proj', f)
    got = s.get(_sid('proj', f))
    assert got['evidence'] == {'location': 'https://x.com/a.js', 'masked': 'AKIA…20'}


# ── set_status + events ───────────────────────────────────────────────────────

def test_set_status_logs_transition(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('proj', f)
    fid = _sid('proj', f)
    s.set_status(fid, 'IN_PROGRESS', note='triaging')
    row = s.set_status(fid, 'IGNORED', source='user')
    assert row['status'] == 'IGNORED' and row['status_source'] == 'user'
    events = s.events(fid)
    assert [e['type'] for e in events] == ['CREATED', 'STATUS_CHANGED',
                                           'STATUS_CHANGED']
    last = events[-1]
    assert last['from_status'] == 'IN_PROGRESS' and last['to_status'] == 'IGNORED'


def test_set_status_no_event_when_unchanged(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('proj', f)
    s.set_status(_sid('proj', f), 'OPEN')              # already OPEN
    assert [e['type'] for e in s.events(_sid('proj', f))] == ['CREATED']


def test_set_status_custom_event_type(tmp_path):
    # The lifecycle layer (T1.4) records RESOLVED_AUTO / REOPENED via event_type.
    s = _store(tmp_path)
    f = _finding()
    s.upsert('proj', f)
    s.set_status(_sid('proj', f), 'FIXED', source='auto', event_type='RESOLVED_AUTO')
    assert s.events(_sid('proj', f))[-1]['type'] == 'RESOLVED_AUTO'


def test_set_status_validates(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('proj', f)
    with pytest.raises(ValueError):
        s.set_status(_sid('proj', f), 'BOGUS')
    with pytest.raises(KeyError):
        s.set_status('deadbeef', 'FIXED')


# ── queries / summary ─────────────────────────────────────────────────────────

def test_list_filters_and_project_scoping(tmp_path):
    s = _store(tmp_path)
    s.upsert('p1', _finding(title='A', rule_id='a', severity='high'))
    s.upsert('p1', _finding(title='B', rule_id='b', severity='low'))
    s.upsert('p2', _finding(title='C', rule_id='c', severity='high'))
    assert len(s.list_findings('p1')) == 2
    assert len(s.list_findings('p2')) == 1
    assert {f['title'] for f in s.list_findings('p1', severity='high')} == {'A'}


def test_projects_lists_distinct_with_counts(tmp_path):
    s = _store(tmp_path)
    s.upsert('p1', _finding(title='A', rule_id='a'))
    s.upsert('p1', _finding(title='B', rule_id='b'))
    s.upsert('p2', _finding(title='C', rule_id='c'))
    s.set_status(_sid('p1', _finding(title='B', rule_id='b')), 'FIXED')  # inactive
    by_name = {p['project']: p for p in s.projects()}
    assert set(by_name) == {'p1', 'p2'}
    assert by_name['p1'] == {'project': 'p1', 'total': 2, 'active': 1}
    assert by_name['p2'] == {'project': 'p2', 'total': 1, 'active': 1}


def test_projects_empty_when_no_findings(tmp_path):
    assert _store(tmp_path).projects() == []


def test_active_and_summary_exclude_inactive(tmp_path):
    s = _store(tmp_path)
    a = _finding(title='A', rule_id='a')
    b = _finding(title='B', rule_id='b')
    c = _finding(title='C', rule_id='c')
    for f in (a, b, c):
        s.upsert('proj', f)
    s.set_status(_sid('proj', b), 'FIXED')
    s.set_status(_sid('proj', c), 'FALSE_POSITIVE')
    assert {f['title'] for f in s.active_findings('proj')} == {'A'}   # only OPEN
    summary = s.summary('proj')
    assert summary['total'] == 3 and summary['active'] == 1
    assert summary['by_status']['FIXED'] == 1
    assert summary['by_status']['FALSE_POSITIVE'] == 1


# ── sync() lifecycle (T1.4) ───────────────────────────────────────────────────

def _raw(title, severity='Medium', detail='x', source=''):
    return {'title': title, 'severity': severity, 'detail': detail,
            'source': source}


def test_sync_creates_then_recurs(tmp_path):
    s = _store(tmp_path)
    scan1 = [_raw('Weak Content-Security-Policy'), _raw('HSTS max-age too short')]
    r1 = s.sync('p', 's1', scan1)
    assert len(r1['new']) == 2 and r1['summary']['active'] == 2
    r2 = s.sync('p', 's2', scan1)
    assert len(r2['new']) == 0 and len(r2['recurring']) == 2


def test_sync_auto_fixes_absent_in_scope(tmp_path):
    s = _store(tmp_path)
    s.sync('p', 's1', [_raw('Weak Content-Security-Policy'),
                       _raw('HSTS max-age too short')])
    # Second scan: CSP gone; vulns phase ran (everything in scope) → auto-FIXED.
    r2 = s.sync('p', 's2', [_raw('HSTS max-age too short')],
                in_scope=lambda src: True)
    assert [f['title'] for f in r2['resolved']] == ['Weak Content-Security-Policy']
    assert r2['summary']['by_status']['FIXED'] == 1


def test_sync_does_not_fix_out_of_scope(tmp_path):
    s = _store(tmp_path)
    s.sync('p', 's1', [_raw('No SPF record', source='dns')])
    # DNS phase NOT run this scan → its finding must stay OPEN, not auto-FIXED.
    r2 = s.sync('p', 's2', [], in_scope=lambda src: src.lower() != 'dns')
    assert r2['resolved'] == []
    assert s.summary('p')['by_status']['OPEN'] == 1


def test_sync_sticky_ignored_not_auto_fixed(tmp_path):
    s = _store(tmp_path)
    s.sync('p', 's1', [_raw('Weak Content-Security-Policy')])
    csp = scoped_id('p', fingerprint('header', 'weak-content-security-policy'))
    s.set_status(csp, 'IGNORED')
    r2 = s.sync('p', 's2', [], in_scope=lambda src: True)   # absent this scan
    assert r2['resolved'] == []                             # sticky, not fixed
    assert s.get(csp)['status'] == 'IGNORED'


def test_sync_reopens_fixed_when_seen_again(tmp_path):
    s = _store(tmp_path)
    csp = [_raw('Weak Content-Security-Policy')]
    s.sync('p', 's1', csp)
    s.sync('p', 's2', [], in_scope=lambda src: True)        # → auto-FIXED
    fid = scoped_id('p', fingerprint('header', 'weak-content-security-policy'))
    assert s.get(fid)['status'] == 'FIXED'
    r3 = s.sync('p', 's3', csp)                             # reappears → REOPENED
    assert len(r3['reopened']) == 1 and s.get(fid)['status'] == 'OPEN'
    assert s.events(fid)[-1]['type'] == 'REOPENED'


# ── cross-project isolation (B fix: location-less findings don't collide) ──────

def test_location_less_finding_does_not_collide_across_projects(tmp_path):
    # A DNS / host-level finding has no URL → its fingerprint is identical for
    # two domains. The store must still keep them as separate rows per project.
    s = _store(tmp_path)
    dns = {'title': 'No SPF record', 'category': 'dns', 'rule_id': 'spf',
           'severity': 'medium', 'evidence': None,
           'id': fingerprint('dns', 'spf')}          # location '' → shared fp
    s.upsert('a.com', dns)
    s.upsert('b.com', dns)
    assert s.summary('a.com')['total'] == 1
    assert s.summary('b.com')['total'] == 1
    assert s.summary()['total'] == 2                  # two distinct rows
    # Triaging one project's row leaves the other untouched.
    s.set_status(scoped_id('a.com', dns['id']), 'IGNORED')
    assert s.get(scoped_id('a.com', dns['id']))['status'] == 'IGNORED'
    assert s.get(scoped_id('b.com', dns['id']))['status'] == 'OPEN'
