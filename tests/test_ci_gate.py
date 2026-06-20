"""CI/CD gate policy (core/ci_gate.py, EPIC 16 F4) — pure, offline.

evaluate_gate turns scan-diff events into a pass/fail decision at a severity
threshold; exit_code/summary_line are the CLI-facing helpers.
"""

from core import ci_gate


def _ev(sev, title='x'):
    return {'type': 't', 'title': title, 'severity': sev}


def test_fail_on_high_triggers_on_high_and_critical():
    events = [_ev('critical', 'a'), _ev('high', 'b'), _ev('medium', 'c'),
              _ev('low', 'd'), _ev('info', 'e')]
    r = ci_gate.evaluate_gate(events, fail_on='high')
    assert r['fail'] is True
    assert r['total'] == 2
    assert r['counts'] == {'critical': 1, 'high': 1}
    assert ci_gate.exit_code(r) == 1


def test_fail_on_critical_ignores_high():
    events = [_ev('high'), _ev('high')]
    r = ci_gate.evaluate_gate(events, fail_on='critical')
    assert r['fail'] is False and r['total'] == 0
    assert ci_gate.exit_code(r) == 0


def test_fail_on_info_catches_everything():
    r = ci_gate.evaluate_gate([_ev('info')], fail_on='info')
    assert r['fail'] is True and r['total'] == 1


def test_empty_or_none_passes():
    assert ci_gate.evaluate_gate([])['fail'] is False
    assert ci_gate.evaluate_gate(None)['fail'] is False
    assert ci_gate.exit_code(ci_gate.evaluate_gate([])) == 0


def test_non_dict_events_skipped():
    r = ci_gate.evaluate_gate(['nope', None, _ev('high')], fail_on='high')
    assert r['total'] == 1


def test_unknown_fail_on_defaults_to_high():
    r = ci_gate.evaluate_gate([_ev('high')], fail_on='bogus')
    assert r['fail_on'] == 'bogus' and r['fail'] is True   # threshold defaults to high


def test_summary_line_pass_and_fail():
    assert 'PASS' in ci_gate.summary_line(ci_gate.evaluate_gate([]))
    fail = ci_gate.evaluate_gate([_ev('high'), _ev('critical')], fail_on='high')
    line = ci_gate.summary_line(fail)
    assert 'FAIL' in line and '2 new' in line
