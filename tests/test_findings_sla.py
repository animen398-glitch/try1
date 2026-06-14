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
