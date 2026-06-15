"""Tests for core/findings_sla.py — severity-based SLA derivation (pure, offline)."""

from datetime import datetime, timedelta

from core import findings_sla as sla


def _finding(severity='high', status='OPEN', first_seen=None):
    return {'severity': severity, 'status': status,
            'first_seen_at': (first_seen or datetime.now()).isoformat(timespec='seconds')}


def test_sla_days_defaults_and_no_sla_for_info():
    assert sla.sla_days('critical') == 7
    assert sla.sla_days('high') == 30
    assert sla.sla_days('medium') == 90
    assert sla.sla_days('low') == 120
    assert sla.sla_days('info') is None
    assert sla.sla_days('unknown') is None


def test_sla_days_override_wins():
    assert sla.sla_days('high', {'high': 14}) == 14


def test_within_sla_not_breached():
    now = datetime(2026, 6, 15)
    f = _finding('high', first_seen=now - timedelta(days=10))   # 10 < 30
    st = sla.sla_status(f, now)
    assert st['applicable'] is True
    assert st['breached'] is False
    assert st['age_days'] == 10
    assert st['sla_days'] == 30
    assert st['days_left'] == 20


def test_breached_when_past_window():
    now = datetime(2026, 6, 15)
    f = _finding('high', first_seen=now - timedelta(days=31))   # 31 > 30
    st = sla.sla_status(f, now)
    assert st['breached'] is True
    assert st['days_left'] == -1                                # one day overdue


def test_exactly_at_boundary_not_breached():
    now = datetime(2026, 6, 15)
    f = _finding('high', first_seen=now - timedelta(days=30))   # exactly due
    st = sla.sla_status(f, now)
    assert st['breached'] is False                              # now == due, not past
    assert st['days_left'] == 0


def test_inactive_finding_has_no_sla():
    now = datetime(2026, 6, 15)
    for status in ('FIXED', 'IGNORED', 'FALSE_POSITIVE'):
        f = _finding('high', status=status, first_seen=now - timedelta(days=99))
        assert sla.sla_status(f, now) == {'applicable': False}


def test_info_severity_not_applicable():
    now = datetime(2026, 6, 15)
    f = _finding('info', first_seen=now - timedelta(days=999))
    assert sla.sla_status(f, now) == {'applicable': False}


def test_annotate_and_breached_count():
    now = datetime(2026, 6, 15)
    findings = [
        _finding('critical', first_seen=now - timedelta(days=10)),   # 10 > 7  breached
        _finding('high', first_seen=now - timedelta(days=5)),        # 5 < 30  ok
        _finding('high', status='FIXED', first_seen=now - timedelta(days=99)),  # inactive
        _finding('info', first_seen=now - timedelta(days=999)),      # no sla
    ]
    sla.annotate(findings, now)
    assert findings[0]['sla']['breached'] is True
    assert findings[1]['sla']['breached'] is False
    assert findings[2]['sla'] == {'applicable': False}
    assert sla.breached_count(findings, now) == 1


# ── reopen resets the SLA clock (current episode, not original discovery) ──────

def test_reopen_restarts_sla_clock():
    now = datetime(2026, 6, 15)
    # Discovered 200 days ago (well past a 30-day high window) but reopened 2
    # days ago → measured from the reopen, it is NOT breached.
    f = _finding('high', first_seen=now - timedelta(days=200))
    f['id'] = 'fid-1'
    reopened = {'fid-1': (now - timedelta(days=2)).isoformat(timespec='seconds')}
    st = sla.sla_status(f, now, reopened_at=reopened['fid-1'])
    assert st['breached'] is False
    assert st['age_days'] == 2
    assert st['reference_at'].startswith('2026-06-13')
    # Without the reopen date it falls back to first_seen → breached.
    assert sla.sla_status(f, now)['breached'] is True
    # annotate threads the reopened map through by finding id.
    sla.annotate([f], now, reopened=reopened)
    assert f['sla']['breached'] is False
    assert sla.breached_count([f], now, reopened=reopened) == 0


def test_reference_is_latest_of_first_seen_and_reopen():
    now = datetime(2026, 6, 15)
    f = _finding('high', first_seen=now - timedelta(days=5))
    # A stale/earlier reopen date must not pull the clock back before first_seen.
    older = (now - timedelta(days=99)).isoformat(timespec='seconds')
    st = sla.sla_status(f, now, reopened_at=older)
    assert st['age_days'] == 5            # first_seen wins (it is the later date)


# ── bucket classifier ─────────────────────────────────────────────────────────

def test_sla_bucket_classification():
    now = datetime(2026, 6, 15)
    breached = sla.sla_status(_finding('high', first_seen=now - timedelta(days=40)), now)
    due_soon = sla.sla_status(_finding('high', first_seen=now - timedelta(days=27)), now)
    on_track = sla.sla_status(_finding('high', first_seen=now - timedelta(days=2)), now)
    assert sla.sla_bucket(breached) == 'breached'
    assert sla.sla_bucket(due_soon) == 'due_soon'      # 3 days left ≤ warn(7)
    assert sla.sla_bucket(on_track) == 'on_track'
    assert sla.sla_bucket({'applicable': False}) is None
    # the status dict carries the bucket already
    assert breached['bucket'] == 'breached'
    assert due_soon['bucket'] == 'due_soon'


# ── aggregate summary (aging histogram + per-severity) ────────────────────────

def test_sla_summary_buckets_and_aging():
    now = datetime(2026, 6, 15)
    findings = [
        _finding('critical', first_seen=now - timedelta(days=10)),  # breached (7)
        _finding('high', first_seen=now - timedelta(days=27)),      # due_soon
        _finding('high', first_seen=now - timedelta(days=2)),       # on_track
        _finding('high', status='FIXED', first_seen=now - timedelta(days=99)),
        _finding('info', first_seen=now - timedelta(days=5)),       # no SLA
    ]
    out = sla.sla_summary(findings, now)
    assert out['applicable'] == 3
    assert out['breached'] == 1
    assert out['due_soon'] == 1
    assert out['on_track'] == 1
    assert out['by_severity']['high'] == {
        'breached': 0, 'due_soon': 1, 'on_track': 1, 'total': 2}
    assert out['by_severity']['critical']['breached'] == 1
    # aging histogram: the 2-day high (0-7), the 27-day high (8-30),
    # the 10-day critical (8-30); info/fixed excluded.
    assert out['aging'] == {'0-7': 1, '8-30': 2, '31-90': 0, '90+': 0}


# ── timeline-shaped breach events ─────────────────────────────────────────────

def test_sla_events_only_for_active_breached():
    now = datetime(2026, 6, 15)
    f_breached = _finding('high', first_seen=now - timedelta(days=40))
    f_breached['id'], f_breached['title'] = 'fid-b', 'Stale secret'
    f_ok = _finding('high', first_seen=now - timedelta(days=2))
    f_fixed = _finding('critical', status='FIXED', first_seen=now - timedelta(days=99))
    events = sla.sla_events([f_breached, f_ok, f_fixed], now)
    assert len(events) == 1
    ev = events[0]
    assert ev['type'] == 'sla_breach'
    assert ev['section'] == 'findings'
    assert ev['scan_id'] is None
    assert ev['severity'] == 'high'
    assert 'Stale secret' in ev['title']
    # high window is 30d from first_seen (40 days ago) → due 10 days ago.
    assert ev['at'] == (now - timedelta(days=10)).isoformat(timespec='seconds')
