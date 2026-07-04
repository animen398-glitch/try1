"""core/project_compare.py
Focused A-vs-B comparison of two projects.

The portfolio view (``core.portfolio``) answers "how does my whole estate look?";
scan diff (``core.scan_diff``) compares two scans of *one* project; audit compare
(``core.audit_compare``) diffs two audit runs. This module fills the remaining
gap: a side-by-side comparison of **two different projects** — their latest risk,
exposure counts and active findings, with a per-metric delta and which side is
worse.

Pure / offline / derive-on-read (invariant I3/I5): the aggregator
``compare_projects`` is a pure function over already-built ``portfolio`` rows;
``load_project_compare`` is the thin loader. It never recomputes risk — it reuses
the numbers ``portfolio.build_portfolio`` already folded from each project's
``metadata.json`` + the findings store.
"""

import csv
import io
from typing import Dict, List

from core.executive_summary import RISK_ORDER

# Worst-to-best rank so a lower index = worse risk level (mirrors portfolio).
_RISK_RANK = {level: i for i, level in enumerate(RISK_ORDER)}

# Numeric metrics compared side by side. For every one of these, a *higher* value
# is worse (more risk / more exposure / more open work), so "worse" is just the
# larger side. (label, portfolio-row key).
_COMPARE_METRICS: List = [
    ('risk_score',      'Risk score'),
    ('attack_surface',  'Attack surface'),
    ('active_findings', 'Active findings'),
    ('secrets',         'Secrets'),
    ('high',            'High severity'),
    ('medium',          'Medium severity'),
    ('source_map_leaks', 'Source-map leaks'),
    ('weak_cookies',    'Weak cookies'),
    ('graphql',         'GraphQL endpoints'),
    ('graphql_introspection', 'GraphQL introspection'),
]


def _num(value):
    """Coerce to float, or ``None`` if missing/unparseable (keeps 'unknown'
    distinct from a real 0 — a never-scanned metric is not a clean 0)."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _rows_by_slug(rows: List[Dict]) -> Dict[str, Dict]:
    return {r.get('slug'): r for r in rows or [] if isinstance(r, dict) and r.get('slug')}


def _metric_row(key: str, label: str, row_a: Dict, row_b: Dict) -> Dict:
    """One side-by-side metric line: values, delta (b − a) and the worse side.

    ``delta`` / ``worse`` are ``None`` when either value is unknown, so an
    un-scanned project never fabricates a 0 comparison."""
    a = _num(row_a.get(key))
    b = _num(row_b.get(key))
    delta = None
    worse = None
    if a is not None and b is not None:
        delta = b - a
        # Higher is worse for every numeric metric here.
        worse = 'tie' if a == b else ('b' if b > a else 'a')
    return {'key': key, 'label': label, 'a': a, 'b': b,
            'delta': delta, 'worse': worse}


def _risk_level_compare(row_a: Dict, row_b: Dict) -> Dict:
    """Compare the categorical risk *level* (worse = lower rank in RISK_ORDER)."""
    la = row_a.get('risk_level')
    lb = row_b.get('risk_level')
    ra = _RISK_RANK.get(la)
    rb = _RISK_RANK.get(lb)
    worse = None
    if ra is not None and rb is not None:
        worse = 'tie' if ra == rb else ('a' if ra < rb else 'b')
    return {'key': 'risk_level', 'label': 'Risk level', 'a': la, 'b': lb,
            'delta': None, 'worse': worse}


def compare_projects(rows: List[Dict], slug_a: str, slug_b: str) -> Dict:
    """Side-by-side comparison of two projects from portfolio ``rows`` (pure).

    ``rows`` is ``portfolio.build_portfolio(...)['rows']``. Returns
    ``{a, b, metrics, summary}`` where ``a``/``b`` are compact project headers,
    ``metrics`` is the ordered list of side-by-side lines (risk level first, then
    the numeric metrics), and ``summary`` counts how many metrics each side is
    worse on. Raises ``ValueError`` if either slug is not in ``rows``.
    """
    by_slug = _rows_by_slug(rows)
    if slug_a not in by_slug:
        raise ValueError(f'project not found: {slug_a}')
    if slug_b not in by_slug:
        raise ValueError(f'project not found: {slug_b}')
    row_a, row_b = by_slug[slug_a], by_slug[slug_b]

    metrics = [_risk_level_compare(row_a, row_b)]
    for key, label in _COMPARE_METRICS:
        metrics.append(_metric_row(key, label, row_a, row_b))

    summary = {'a_worse': 0, 'b_worse': 0, 'tie': 0}
    for m in metrics:
        if m['worse'] == 'a':
            summary['a_worse'] += 1
        elif m['worse'] == 'b':
            summary['b_worse'] += 1
        elif m['worse'] == 'tie':
            summary['tie'] += 1

    def _header(row: Dict) -> Dict:
        return {'slug': row.get('slug'), 'url': row.get('url') or '',
                'risk_level': row.get('risk_level'),
                'risk_score': row.get('risk_score'),
                'scan_count': row.get('scan_count'),
                'updated_at': row.get('updated_at') or ''}

    return {'a': _header(row_a), 'b': _header(row_b),
            'metrics': metrics, 'summary': summary}


def _num_str(value) -> str:
    """Render a metric value, showing an integral float as a plain int (the values
    come through ``_num`` as floats, so 20.0 should read as 20)."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _cell(value) -> str:
    """Display a metric value, unknown → em dash."""
    return '—' if value is None else _num_str(value)


def _delta_text(delta) -> str:
    return '—' if delta is None else f'{delta:+g}'


def _worse_labels(comparison: Dict) -> Dict:
    sa = (comparison.get('a') or {}).get('slug', 'A')
    sb = (comparison.get('b') or {}).get('slug', 'B')
    return {'a': sa, 'b': sb, 'tie': 'tie', None: '—'}


def render_csv(comparison: Dict) -> str:
    """CSV of a comparison: header ``Metric, <A>, <B>, Delta, Worse`` (the A/B column
    names are the project slugs) + one row per metric. Pure, well-formed via ``csv``."""
    a = comparison.get('a') or {}
    b = comparison.get('b') or {}
    sa, sb = a.get('slug', 'A'), b.get('slug', 'B')
    worse = {'a': sa, 'b': sb, 'tie': 'tie', None: ''}
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Metric', sa, sb, 'Delta', 'Worse'])
    for m in comparison.get('metrics') or []:
        writer.writerow([m.get('label', ''),
                         '' if m.get('a') is None else _num_str(m.get('a')),
                         '' if m.get('b') is None else _num_str(m.get('b')),
                         _delta_text(m.get('delta')),
                         worse.get(m.get('worse'), '')])
    return buf.getvalue()


def render_markdown(comparison: Dict) -> str:
    """Markdown of a comparison: a title, the summary tally, and a metrics table.
    Pure and deterministic (a shareable A-vs-B deliverable)."""
    a = comparison.get('a') or {}
    b = comparison.get('b') or {}
    sa, sb = a.get('slug', 'A'), b.get('slug', 'B')
    worse = _worse_labels(comparison)
    s = comparison.get('summary') or {}
    lines = [
        f'# Project comparison: {sa} vs {sb}', '',
        f'- Worse metrics: {sa} — {s.get("a_worse", 0)}, '
        f'{sb} — {s.get("b_worse", 0)}, tie — {s.get("tie", 0)}', '',
        f'| Metric | {sa} | {sb} | Δ | Worse |',
        '| --- | --- | --- | --- | --- |',
    ]
    for m in comparison.get('metrics') or []:
        lines.append(
            f"| {m.get('label', '')} | {_cell(m.get('a'))} | {_cell(m.get('b'))} "
            f"| {_delta_text(m.get('delta'))} | {worse.get(m.get('worse'), '—')} |")
    return '\n'.join(lines) + '\n'


def load_project_compare(base: str, slug_a: str, slug_b: str) -> Dict:
    """Load the portfolio under ``base`` and compare two projects (thin loader).

    Offline, read-only — call from a worker thread (I4). Raises ``ValueError`` if
    either slug is missing (mirrors ``compare_projects``)."""
    from core.portfolio import load_portfolio
    rows = load_portfolio(base).get('rows', [])
    return compare_projects(rows, slug_a, slug_b)
