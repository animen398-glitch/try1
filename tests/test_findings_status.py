"""Tests for Findings Management (core/findings_status.py, roadmap #14).

All logic is pure transforms over dicts; ``now`` is injected so timestamps are
deterministic.
"""

import pytest

from core import findings_status as fs


def _f(title, severity='High', source=''):
    return {'title': title, 'severity': severity, 'source': source}


# ── fingerprint (pure) ────────────────────────────────────────────────────────

def test_fingerprint_stable_across_volatile_counts():
    a = fs.fingerprint(_f('Missing security headers (3)', 'Medium'))
    b = fs.fingerprint(_f('Missing security headers (5)', 'Medium'))
    assert a == b                                   # digit run masked


def test_fingerprint_distinguishes_severity_and_title():
    assert fs.fingerprint(_f('X', 'High')) != fs.fingerprint(_f('X', 'Medium'))
    assert fs.fingerprint(_f('X')) != fs.fingerprint(_f('Y'))


# ── apply (pure merge) ────────────────────────────────────────────────────────

def test_apply_registers_new_as_open():
    state = fs.apply({}, [_f('A'), _f('B')], now='2024-01-01T00:00:00', scan_id='s1')
    assert len(state) == 2
    assert all(r['status'] == 'open' and r['present'] for r in state.values())
    assert all(r['first_scan'] == 's1' for r in state.values())


def test_apply_preserves_status_and_marks_absent():
    s1 = fs.apply({}, [_f('A'), _f('B')], now='2024-01-01T00:00:00', scan_id='s1')
    fp_a = fs.fingerprint(_f('A'))
    s1 = fs.set_status(s1, fp_a, 'fixed', now='2024-01-02T00:00:00')
    # Next scan: A is gone, B remains.
    s2 = fs.apply(s1, [_f('B')], now='2024-02-01T00:00:00', scan_id='s2')
    assert s2[fp_a]['status'] == 'fixed'            # status preserved
    assert s2[fp_a]['present'] is False             # no longer detected
    assert s2[fp_a]['first_seen'] == '2024-01-01T00:00:00'   # not reset
    fp_b = fs.fingerprint(_f('B'))
    assert s2[fp_b]['present'] is True and s2[fp_b]['last_scan'] == 's2'


def test_apply_does_not_mutate_input():
    s1 = fs.apply({}, [_f('A')], now='2024-01-01T00:00:00')
    snapshot = {k: dict(v) for k, v in s1.items()}
    fs.apply(s1, [_f('A'), _f('B')], now='2024-02-01T00:00:00')
    assert s1 == snapshot                           # original untouched


# ── set_status (pure) ─────────────────────────────────────────────────────────

def test_set_status_validates():
    s = fs.apply({}, [_f('A')], now='2024-01-01T00:00:00')
    fp = fs.fingerprint(_f('A'))
    s2 = fs.set_status(s, fp, 'in_progress', note='looking into it')
    assert s2[fp]['status'] == 'in_progress' and s2[fp]['note'] == 'looking into it'
    with pytest.raises(ValueError):
        fs.set_status(s, fp, 'bogus')
    with pytest.raises(KeyError):
        fs.set_status(s, 'deadbeef', 'fixed')


# ── decorate / summarize / is_active (pure) ──────────────────────────────────

def test_decorate_stamps_status_default_open():
    s = fs.apply({}, [_f('A')], now='2024-01-01T00:00:00')
    fp = fs.fingerprint(_f('A'))
    s = fs.set_status(s, fp, 'ignored')
    out = fs.decorate([_f('A'), _f('B')], s)
    by_title = {f['title']: f for f in out}
    assert by_title['A']['status'] == 'ignored'
    assert by_title['B']['status'] == 'open'        # unknown → open
    assert all('fingerprint' in f for f in out)


def test_is_active_and_summarize():
    s = fs.apply({}, [_f('A'), _f('B'), _f('C')], now='2024-01-01T00:00:00')
    s = fs.set_status(s, fs.fingerprint(_f('A')), 'fixed')
    s = fs.set_status(s, fs.fingerprint(_f('B')), 'ignored')
    summary = fs.summarize(s)
    assert summary['total'] == 3 and summary['active'] == 1   # only C active
    assert summary['by_status']['fixed'] == 1
    assert summary['by_status']['ignored'] == 1
    assert fs.is_active({'status': 'open'}) and not fs.is_active({'status': 'fixed'})


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline():
    s = fs.apply({}, [_f('Plain HTTP', 'High')], now='2024-01-01T00:00:00')
    page = fs.render_html(s)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert 'Plain HTTP' in page and 'Открыто' in page


def test_render_html_empty():
    assert 'пока нет' in fs.render_html({})


# ── risk-engine integration: fixed/ignored drop out ──────────────────────────

def test_build_summary_excludes_inactive_findings():
    from core.executive_summary import build_summary
    findings = [
        {'title': 'Plain HTTP', 'severity': 'High', 'status': 'open'},
        {'title': 'Weak CSP', 'severity': 'Medium', 'status': 'fixed'},
        {'title': 'CMS info', 'severity': 'Info', 'status': 'ignored'},
    ]
    report = {'phases': {'vulns': {'status': 'Success', 'findings': findings,
                                   'summary': {'high': 1, 'medium': 1, 'info': 1,
                                               'risk_score': 8}}}}
    summary = build_summary(report)
    assert summary['metrics']['high'] == 1          # the open High counts
    assert summary['metrics']['medium'] == 0        # fixed dropped
    assert summary['metrics']['info'] == 0          # ignored dropped


def test_build_summary_unchanged_without_statuses():
    from core.executive_summary import build_summary
    # No 'status' on findings → trust the precomputed summary verbatim.
    report = {'phases': {'vulns': {'status': 'Success',
                                   'findings': [{'title': 'X', 'severity': 'Medium'}],
                                   'summary': {'high': 0, 'medium': 1, 'info': 0,
                                               'risk_score': 2}}}}
    summary = build_summary(report)
    assert summary['metrics']['medium'] == 1
