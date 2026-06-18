"""core/trends.py
Per-project trend analytics — derive-on-read over a metric series (EPIC 4).

The platform already *builds* the per-scan metric series (``timeline.build_series``)
and *visualizes* it (report sparklines, the Overview tab). What was missing is the
**analytics**: for each tracked metric, how it moved across a project's scan history
— the current value, the baseline (first scan), the total change since then, the
direction, and the peak/low. So a glance answers "is risk trending up?" without
re-reading every scan.

Pure / stdlib and offline (invariants I1/I5): a function over an already-built
series; it never recomputes a scan or touches the network. The change *history* is
the companion view (``timeline.build_events``) — this module is the trend half.
"""

from typing import Dict, List, Optional

# The metrics ``timeline.build_series`` carries, in display priority.
METRICS = ('risk_score', 'attack_surface', 'secrets', 'high', 'medium')


def _clean(x):
    """A whole float reads as an int (risk_score 50.0 → 50); other values as-is."""
    return int(x) if isinstance(x, float) and x.is_integer() else x


def _nums(series: List[Dict], key: str) -> List[float]:
    """Numeric values of ``key`` across the series, skipping missing/unparseable
    points (a never-scored metric leaves a gap, not a fake 0)."""
    out: List[float] = []
    for p in series or []:
        if not isinstance(p, dict):
            continue
        try:
            out.append(float(p.get(key)))
        except (TypeError, ValueError):
            continue
    return out


def _direction(values: List[float]) -> str:
    """``up`` / ``down`` / ``flat`` — current vs the first point (a metric with a
    single point, or no net change, is ``flat``)."""
    if len(values) < 2:
        return 'flat'
    delta = values[-1] - values[0]
    if delta > 0:
        return 'up'
    if delta < 0:
        return 'down'
    return 'flat'


def metric_trend(series: List[Dict], key: str) -> Optional[Dict]:
    """Trend of one metric over the series, or ``None`` if it has no numeric point.

    ``{metric, n, current, baseline, delta_total, direction, peak, low}`` —
    ``baseline`` is the first scan, ``delta_total`` the change since then (vs the
    immediately-previous scan is ``portfolio``'s ``risk_delta``)."""
    vals = _nums(series, key)
    if not vals:
        return None
    return {
        'metric': key,
        'n': len(vals),
        'current': _clean(vals[-1]),
        'baseline': _clean(vals[0]),
        'delta_total': _clean(vals[-1] - vals[0]),
        'direction': _direction(vals),
        'peak': _clean(max(vals)),
        'low': _clean(min(vals)),
    }


def trend_summary(series: List[Dict]) -> Dict[str, Dict]:
    """Per-metric trend over a project's scan series — ``{metric: {...}}``.

    Only metrics with at least one numeric point appear; an empty/single-scan
    series yields a sparse/flat summary. The single entry point for the report
    card, the web ``/timeline`` view and any CSV/rollup over trends."""
    out: Dict[str, Dict] = {}
    for key in METRICS:
        t = metric_trend(series, key)
        if t is not None:
            out[key] = t
    return out


def risk_direction(series: List[Dict]) -> str:
    """Shorthand: the risk-score trend direction (``up``/``down``/``flat``) — the
    one signal a cross-project rollup (portfolio) wants per project."""
    return _direction(_nums(series, 'risk_score'))
