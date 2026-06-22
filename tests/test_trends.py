"""Per-project trend analytics (core/trends.py, EPIC 4) — pure, offline.

Operates on an already-built metric series (timeline.build_series shape):
direction, baseline/delta vs first scan, peak/low, gap-tolerance.
"""

from core import trends


def _series(*risk):
    return [{'scan_id': f's{i}', 'at': f'2026-06-1{i}', 'risk_score': r,
             'attack_surface': r // 2, 'secrets': 0, 'high': 0, 'medium': 0}
            for i, r in enumerate(risk)]


def test_metric_trend_rising():
    t = trends.metric_trend(_series(10, 25, 60), 'risk_score')
    assert t['n'] == 3 and t['current'] == 60 and t['baseline'] == 10
    assert t['delta_total'] == 50 and t['direction'] == 'up'
    assert t['peak'] == 60 and t['low'] == 10


def test_metric_trend_falling_and_peak_mid():
    t = trends.metric_trend(_series(40, 80, 30), 'risk_score')
    assert t['direction'] == 'down' and t['delta_total'] == -10
    assert t['peak'] == 80 and t['low'] == 30


def test_single_scan_is_flat():
    t = trends.metric_trend(_series(20), 'risk_score')
    assert t['direction'] == 'flat' and t['delta_total'] == 0 and t['n'] == 1


def test_whole_floats_read_as_ints():
    t = trends.metric_trend([{'risk_score': 50.0}, {'risk_score': 12.0}], 'risk_score')
    assert t['current'] == 12 and isinstance(t['current'], int)


def test_gaps_skipped_not_zeroed():
    # A None point is a gap (never-scored), not a real 0 that would skew min/dir.
    t = trends.metric_trend([{'risk_score': 30}, {'risk_score': None},
                             {'risk_score': 45}], 'risk_score')
    assert t['n'] == 2 and t['low'] == 30 and t['direction'] == 'up'


def test_metric_trend_none_without_numbers():
    assert trends.metric_trend([{'risk_score': None}], 'risk_score') is None
    assert trends.metric_trend([], 'risk_score') is None


def test_trend_summary_covers_metrics_and_risk_direction():
    s = _series(10, 60)
    summary = trends.trend_summary(s)
    assert set(summary) >= {'risk_score', 'attack_surface'}
    assert summary['risk_score']['direction'] == 'up'
    assert trends.risk_direction(s) == 'up'
    assert trends.trend_summary([]) == {}


def test_trend_summary_trends_detection_metrics():
    # Exposure-hygiene counts are first-class trend metrics; a metric with no
    # numeric point in the history is omitted (not faked).
    s = [{'scan_id': 's0', 'risk_score': 10, 'weak_cookies': 1},
         {'scan_id': 's1', 'risk_score': 10, 'weak_cookies': 4}]
    summary = trends.trend_summary(s)
    assert summary['weak_cookies']['direction'] == 'up'
    assert summary['weak_cookies']['delta_total'] == 3
    assert 'graphql' not in summary           # never present → omitted, not zeroed
