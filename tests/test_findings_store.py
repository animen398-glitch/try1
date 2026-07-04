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

def test_sync_persists_finding_evidence_refs(tmp_path):
    s = _store(tmp_path)
    raw = {
        'title': 'Leaked secret',
        'severity': 'High',
        'source': 'secret',
        'location': 'https://x.com',
        'evidence_refs': [{
            'artifact_id': 'sha256:abc',
            'path': 'api/api_keys.json',
            'phase': 'api',
        }],
    }

    s.sync('proj', 'scan-1', [raw])
    row = s.list_findings('proj')[0]

    assert row['evidence']['evidence_refs'] == raw['evidence_refs']


def test_sync_refreshes_existing_finding_evidence_refs(tmp_path):
    s = _store(tmp_path)
    base = {
        'title': 'Leaked secret',
        'severity': 'High',
        'source': 'secret',
        'location': 'https://x.com',
    }
    s.sync('proj', 'scan-1', [{**base, 'evidence_refs': [{
        'artifact_id': 'sha256:old', 'path': 'api/api_keys.json',
        'phase': 'api',
    }]}])

    s.sync('proj', 'scan-2', [{**base, 'evidence_refs': [{
        'artifact_id': 'sha256:new', 'path': 'api/api_keys.json',
        'phase': 'api',
    }]}])
    row = s.list_findings('proj')[0]

    assert row['evidence']['evidence_refs'][0]['artifact_id'] == 'sha256:new'


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


def test_reopen_dates_tracks_latest_reopen(tmp_path):
    # reopen_dates feeds the reopen-aware SLA clock: only findings that actually
    # reopened appear, dated at the most recent REOPENED event.
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    assert s.reopen_dates('proj') == {}                 # never reopened → absent
    s.set_status(sid, 'FIXED', source='auto', event_type='RESOLVED_AUTO')
    s.set_status(sid, 'OPEN', source='auto', event_type='REOPENED',
                 now='2026-01-01T00:00:00')
    s.set_status(sid, 'FIXED', source='auto', event_type='RESOLVED_AUTO')
    s.set_status(sid, 'OPEN', source='auto', event_type='REOPENED',
                 now='2026-06-01T00:00:00')
    assert s.reopen_dates('proj') == {sid: '2026-06-01T00:00:00'}   # latest wins
    # project-scoped: an unrelated project does not leak in.
    assert s.reopen_dates('other') == {}


def test_record_sla_breaches_is_one_shot(tmp_path):
    # The SLA-breach alert guard: a breach is recorded (and thus alertable) once,
    # then suppressed on subsequent runs until the situation changes.
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    # First observation of the breach → marked + returned.
    assert s.record_sla_breaches('proj', [sid]) == [sid]
    assert [e['type'] for e in s.events(sid)].count('SLA_BREACH') == 1
    # Next run, still breached → already alerted → not returned, no new event.
    assert s.record_sla_breaches('proj', [sid]) == []
    assert [e['type'] for e in s.events(sid)].count('SLA_BREACH') == 1


def test_record_sla_breaches_resets_after_reopen(tmp_path):
    # A fixed finding that reappears restarts its SLA clock, so a fresh breach of
    # the new episode is alertable again (its old marker predates the REOPENED).
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    assert s.record_sla_breaches('proj', [sid], now='2026-01-01T00:00:00') == [sid]
    # Fixed, then reopens later (REOPENED newer than the SLA_BREACH marker).
    s.set_status(sid, 'FIXED', source='auto', event_type='RESOLVED_AUTO')
    s.set_status(sid, 'OPEN', source='auto', event_type='REOPENED',
                 now='2026-03-01T00:00:00')
    # The new episode breaches → eligible again (marker '2026-01' < reopen '2026-03').
    assert s.record_sla_breaches('proj', [sid], now='2026-04-01T00:00:00') == [sid]
    assert [e['type'] for e in s.events(sid)].count('SLA_BREACH') == 2


def test_record_sla_breaches_empty_and_dedups(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    assert s.record_sla_breaches('proj', []) == []
    # Duplicate ids in one call collapse to a single marker.
    assert s.record_sla_breaches('proj', [sid, sid]) == [sid]


def test_record_secret_alerts_one_shot_and_reopen_reset(tmp_path):
    # Audit-only secrets have no Scan Diff representation, so the finding-based
    # alert needs the same one-shot, reopen-resetting guard as SLA breaches.
    s = _store(tmp_path)
    f = _finding(title='Leaked secret: AWS Access Key', category='secret')
    sid = _sid('proj', f)
    s.upsert('proj', f)
    # First appearance → marked + returned; second run → suppressed.
    assert s.record_secret_alerts('proj', [sid], now='2026-01-01T00:00:00') == [sid]
    assert [e['type'] for e in s.events(sid)].count('SECRET_ALERTED') == 1
    assert s.record_secret_alerts('proj', [sid]) == []
    assert [e['type'] for e in s.events(sid)].count('SECRET_ALERTED') == 1
    # Fixed, then reappears (REOPENED) → re-eligible to alert on the new episode.
    s.set_status(sid, 'FIXED', source='auto', event_type='RESOLVED_AUTO')
    s.set_status(sid, 'OPEN', source='auto', event_type='REOPENED',
                 now='2026-03-01T00:00:00')
    assert s.record_secret_alerts('proj', [sid], now='2026-04-01T00:00:00') == [sid]
    assert [e['type'] for e in s.events(sid)].count('SECRET_ALERTED') == 2


def test_record_finding_alerts_one_shot(tmp_path):
    # The generic-finding alert guard mirrors SLA/secret: marked + returned once,
    # then suppressed until the situation changes.
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    assert s.record_finding_alerts('proj', [sid]) == [sid]
    assert [e['type'] for e in s.events(sid)].count('FINDING_ALERTED') == 1
    assert s.record_finding_alerts('proj', [sid]) == []
    assert [e['type'] for e in s.events(sid)].count('FINDING_ALERTED') == 1


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


# ── GitHub issue mapping (EPIC 16 wave 2) ─────────────────────────────────────

def test_untracked_for_issue_and_record(tmp_path):
    # The finding → GitHub issue mapping is an ISSUE_CREATED event; a recorded
    # finding drops out of the untracked set (idempotent push).
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    assert s.untracked_for_issue('proj', [sid]) == [sid]
    s.record_issue('proj', sid, 42, 'https://github.com/o/r/issues/42')
    assert s.untracked_for_issue('proj', [sid]) == []
    ev = s.events(sid)[-1]
    assert ev['type'] == 'ISSUE_CREATED'
    import json
    assert json.loads(ev['note']) == {'number': 42,
                                       'url': 'https://github.com/o/r/issues/42'}


def test_untracked_for_issue_resets_after_reopen(tmp_path):
    # A fixed finding that reappears (new REOPENED episode) needs a fresh issue:
    # its old ISSUE_CREATED predates the REOPENED, so it is untracked again.
    s = _store(tmp_path)
    f = _finding()
    sid = _sid('proj', f)
    s.upsert('proj', f)
    s.record_issue('proj', sid, 7, 'u', now='2026-01-01T00:00:00')
    assert s.untracked_for_issue('proj', [sid]) == []
    s.set_status(sid, 'FIXED', source='auto', event_type='RESOLVED_AUTO')
    s.set_status(sid, 'OPEN', source='auto', event_type='REOPENED',
                 now='2026-03-01T00:00:00')
    assert s.untracked_for_issue('proj', [sid]) == [sid]


def test_untracked_for_issue_empty(tmp_path):
    assert _store(tmp_path).untracked_for_issue('proj', []) == []


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


# ── triage: assignment + comments (event-sourced over finding_events) ──────────

def test_assign_latest_wins_and_unassign(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('p', f)
    fid = _sid('p', f)
    assert s.get_assignee(fid) == ''                 # unassigned by default
    s.assign(fid, 'alice')
    assert s.get_assignee(fid) == 'alice'
    s.assign(fid, 'bob')                             # reassign — latest wins
    assert s.get_assignee(fid) == 'bob'
    s.assign(fid, '')                                # unassign
    assert s.get_assignee(fid) == ''


def test_assignees_map_drops_empty(tmp_path):
    s = _store(tmp_path)
    f1, f2 = _finding(location='https://x.com/a'), _finding(location='https://x.com/b')
    s.upsert('p', f1); s.upsert('p', f2)
    s.assign(_sid('p', f1), 'alice')
    s.assign(_sid('p', f2), 'bob')
    s.assign(_sid('p', f2), '')                      # cleared → dropped from map
    assert s.assignees('p') == {_sid('p', f1): 'alice'}


def test_assign_unknown_finding_raises(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(KeyError):
        s.assign('ghost', 'alice')


def test_comments_append_in_order(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('p', f)
    fid = _sid('p', f)
    assert s.comments(fid) == []
    s.add_comment(fid, 'first', author='alice')
    s.add_comment(fid, 'second')                     # anonymous
    thread = s.comments(fid)
    assert [c['text'] for c in thread] == ['first', 'second']
    assert thread[0]['author'] == 'alice' and thread[1]['author'] == ''
    assert all(c['at'] for c in thread)


def test_comment_empty_or_unknown_raises(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('p', f)
    with pytest.raises(ValueError):
        s.add_comment(_sid('p', f), '   ')
    with pytest.raises(KeyError):
        s.add_comment('ghost', 'hi')


# ── bulk triage (multi-finding status / assign) ─────────────────────────────────

def _seed_three(s, project='p'):
    ids = []
    for i in range(3):
        f = _finding(rule_id=f'r{i}', location=f'https://x.com/{i}')
        ids.append(s.upsert(project, f, scan_id='s1')['finding']['id'])
    return ids


def test_bulk_set_status_partitions_updated_unchanged_missing(tmp_path):
    s = _store(tmp_path)
    ids = _seed_three(s)
    s.set_status(ids[2], 'FIXED')                      # already FIXED → unchanged
    out = s.bulk_set_status(ids + ['ghost'], 'FIXED')
    assert set(out['updated']) == {ids[0], ids[1]}
    assert out['unchanged'] == [ids[2]]
    assert out['missing'] == ['ghost']
    # every real finding is now FIXED, each change logged a STATUS_CHANGED event
    assert all(s.get(i)['status'] == 'FIXED' for i in ids)
    assert any(e['type'] == 'STATUS_CHANGED' for e in s.events(ids[0]))


def test_bulk_set_status_unknown_status_raises(tmp_path):
    s = _store(tmp_path)
    ids = _seed_three(s)
    with pytest.raises(ValueError):
        s.bulk_set_status(ids, 'NOPE')


def test_bulk_assign_sets_and_reports_missing(tmp_path):
    s = _store(tmp_path)
    ids = _seed_three(s)
    out = s.bulk_assign(ids + ['ghost'], 'alice')
    assert out['assignee'] == 'alice'
    assert set(out['updated']) == set(ids)
    assert out['missing'] == ['ghost']
    assert all(s.get_assignee(i) == 'alice' for i in ids)


def test_bulk_assign_empty_clears(tmp_path):
    s = _store(tmp_path)
    ids = _seed_three(s)
    s.bulk_assign(ids, 'bob')
    s.bulk_assign(ids, '')                              # '' unassigns
    assert all(s.get_assignee(i) == '' for i in ids)


# ── risk acceptance (v1 overlay: accept / expire / revoke) ──────────────────────

def test_accept_risk_and_state(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    fid = s.upsert('p', f, scan_id='s1')['finding']['id']
    s.accept_risk(fid, reason='low impact', approver='ciso', until='2099-01-01')
    st = s.risk_acceptance_state(fid, today='2026-07-04')
    assert st['accepted'] and not st['expired']
    assert st['reason'] == 'low impact' and st['approver'] == 'ciso'
    # status/risk are untouched by the overlay
    assert s.get(fid)['status'] == 'OPEN'


def test_acceptance_expires_by_until_date(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    fid = s.upsert('p', f, scan_id='s1')['finding']['id']
    s.accept_risk(fid, until='2026-01-01')
    assert s.risk_acceptance_state(fid, today='2026-07-04')['expired'] is True
    assert s.risk_acceptance_state(fid, today='2025-12-01')['expired'] is False


def test_clear_risk_acceptance(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    fid = s.upsert('p', f, scan_id='s1')['finding']['id']
    s.accept_risk(fid, until='2099-01-01')
    s.clear_risk_acceptance(fid)                       # latest event wins
    assert s.risk_acceptance_state(fid)['accepted'] is False


def test_risk_acceptances_lists_current_and_filters_expired(tmp_path):
    s = _store(tmp_path)
    a = s.upsert('p', _finding(rule_id='a', location='https://x/a'),
                 scan_id='s1')['finding']['id']
    b = s.upsert('p', _finding(rule_id='b', location='https://x/b'),
                 scan_id='s1')['finding']['id']
    c = s.upsert('p', _finding(rule_id='c', location='https://x/c'),
                 scan_id='s1')['finding']['id']
    s.accept_risk(a, until='2099-01-01')               # active
    s.accept_risk(b, until='2026-01-01')               # expired
    s.accept_risk(c, until='2099-01-01')
    s.clear_risk_acceptance(c)                          # revoked → excluded
    allrows = s.risk_acceptances('p', today='2026-07-04')
    assert {r['finding_id'] for r in allrows} == {a, b}
    active_only = s.risk_acceptances('p', today='2026-07-04', include_expired=False)
    assert {r['finding_id'] for r in active_only} == {a}


def test_accept_risk_unknown_finding_raises(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(KeyError):
        s.accept_risk('ghost', until='2099-01-01')


# ── risk acceptance → active-risk integration (Option A, derive-on-read) ─────────

def test_active_findings_excludes_current_acceptance(tmp_path):
    s = _store(tmp_path)
    a = s.upsert('p', _finding(rule_id='a', location='https://x/a'),
                 scan_id='s1')['finding']['id']
    b = s.upsert('p', _finding(rule_id='b', location='https://x/b'),
                 scan_id='s1')['finding']['id']
    s.accept_risk(a, until='2099-01-01')                 # current acceptance
    active = {f['id'] for f in s.active_findings('p', today='2026-07-04')}
    assert active == {b}                                 # a is held off the risk view
    # include_accepted returns the full non-inactive set
    allactive = {f['id'] for f in s.active_findings('p', include_accepted=True)}
    assert allactive == {a, b}


def test_active_findings_reincludes_when_acceptance_expires(tmp_path):
    s = _store(tmp_path)
    a = s.upsert('p', _finding(rule_id='a', location='https://x/a'),
                 scan_id='s1')['finding']['id']
    s.accept_risk(a, until='2026-06-01')                 # lapses before 'today'
    assert {f['id'] for f in s.active_findings('p', today='2026-07-04')} == {a}


def test_projects_active_count_excludes_current_acceptance(tmp_path):
    s = _store(tmp_path)
    a = s.upsert('p', _finding(rule_id='a', location='https://x/a'),
                 scan_id='s1')['finding']['id']
    s.upsert('p', _finding(rule_id='b', location='https://x/b'), scan_id='s1')
    row = next(r for r in s.projects(today='2026-07-04') if r['project'] == 'p')
    assert row['total'] == 2 and row['active'] == 2
    s.accept_risk(a, until='2099-01-01')
    row = next(r for r in s.projects(today='2026-07-04') if r['project'] == 'p')
    assert row['total'] == 2 and row['active'] == 1      # accepted drops from active
    # once expired it counts again
    row2 = next(r for r in s.projects(today='2100-01-01') if r['project'] == 'p')
    assert row2['active'] == 2


# ── keyword search (list_findings query=) ───────────────────────────────────────

def test_list_findings_query_matches_title_rule_category(tmp_path):
    s = _store(tmp_path)
    s.upsert('p', _finding(title='Weak Content-Security-Policy', rule_id='csp',
                           category='header', location='https://x/a'), scan_id='s1')
    s.upsert('p', _finding(title='Insecure cookie', rule_id='cookie_flags',
                           category='cookie', location='https://x/b'), scan_id='s1')
    # title substring, case-insensitive
    assert [f['title'] for f in s.list_findings('p', query='security')] == \
        ['Weak Content-Security-Policy']
    # rule_id substring
    assert [f['title'] for f in s.list_findings('p', query='cookie_fl')] == \
        ['Insecure cookie']
    # category substring
    assert [f['title'] for f in s.list_findings('p', query='header')] == \
        ['Weak Content-Security-Policy']
    # no match → empty; blank query → all
    assert s.list_findings('p', query='zzz') == []
    assert len(s.list_findings('p', query='   ')) == 2


def test_bulk_accept_and_clear_risk(tmp_path):
    s = _store(tmp_path)
    ids = _seed_three(s)
    out = s.bulk_accept_risk(ids + ['ghost'], reason='batch', approver='ciso',
                             until='2099-01-01')
    assert set(out['updated']) == set(ids) and out['missing'] == ['ghost']
    for i in ids:
        st = s.risk_acceptance_state(i, today='2026-07-04')
        assert st['accepted'] and st['reason'] == 'batch'
    # bulk revoke
    cl = s.bulk_clear_risk_acceptance(ids)
    assert set(cl['updated']) == set(ids)
    assert all(not s.risk_acceptance_state(i)['accepted'] for i in ids)
