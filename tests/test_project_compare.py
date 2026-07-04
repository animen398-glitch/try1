"""Focused A-vs-B project comparison (core/project_compare.py).

Pure aggregator over portfolio rows + a thin loader. Verifies per-metric deltas
and the "which side is worse" verdict, the risk-level (categorical) comparison,
the summary tally, unknown-value handling, and the missing-slug guard.
"""

import json

import pytest

from core import project_compare as pc


def _row(slug, **kw):
    base = {'slug': slug, 'url': f'https://{slug}', 'risk_level': None,
            'risk_score': None, 'attack_surface': 0, 'active_findings': 0,
            'secrets': 0, 'high': 0, 'medium': 0, 'source_map_leaks': 0,
            'weak_cookies': 0, 'graphql': 0, 'graphql_introspection': 0,
            'scan_count': 1, 'updated_at': '2026-01-01'}
    base.update(kw)
    return base


def _rows():
    return [
        _row('a.com', risk_level='Low', risk_score=20, high=1, secrets=0,
             active_findings=2),
        _row('b.com', risk_level='High', risk_score=70, high=4, secrets=2,
             active_findings=5),
    ]


# ── numeric metrics + worse side ────────────────────────────────────────────────

def test_metric_delta_and_worse_side():
    out = pc.compare_projects(_rows(), 'a.com', 'b.com')
    by_key = {m['key']: m for m in out['metrics']}
    rs = by_key['risk_score']
    assert rs['a'] == 20 and rs['b'] == 70
    assert rs['delta'] == 50            # b − a
    assert rs['worse'] == 'b'           # higher risk score is worse
    assert by_key['secrets']['worse'] == 'b'
    assert by_key['high']['worse'] == 'b'


def test_equal_metric_is_tie():
    rows = [_row('a.com', risk_score=30, medium=3),
            _row('b.com', risk_score=30, medium=3)]
    by_key = {m['key']: m for m in pc.compare_projects(rows, 'a.com', 'b.com')['metrics']}
    assert by_key['risk_score']['worse'] == 'tie'
    assert by_key['medium']['worse'] == 'tie'


def test_worse_side_can_be_a():
    rows = [_row('a.com', risk_score=90, high=9),
            _row('b.com', risk_score=10, high=1)]
    by_key = {m['key']: m for m in pc.compare_projects(rows, 'a.com', 'b.com')['metrics']}
    assert by_key['risk_score']['worse'] == 'a'
    assert by_key['risk_score']['delta'] == -80


# ── risk level (categorical) ────────────────────────────────────────────────────

def test_risk_level_comparison_is_categorical():
    out = pc.compare_projects(_rows(), 'a.com', 'b.com')
    lvl = out['metrics'][0]
    assert lvl['key'] == 'risk_level'          # risk level leads the metric list
    assert lvl['a'] == 'Low' and lvl['b'] == 'High'
    assert lvl['worse'] == 'b'                 # High is worse than Low
    assert lvl['delta'] is None                # categorical → no numeric delta


# ── unknown values ──────────────────────────────────────────────────────────────

def test_unknown_value_yields_no_verdict():
    rows = [_row('a.com', risk_score=None), _row('b.com', risk_score=40)]
    rs = {m['key']: m for m in pc.compare_projects(rows, 'a.com', 'b.com')['metrics']}['risk_score']
    assert rs['a'] is None
    assert rs['delta'] is None and rs['worse'] is None   # never fabricate a 0 compare


# ── summary tally + headers ─────────────────────────────────────────────────────

def test_summary_counts_worse_sides():
    out = pc.compare_projects(_rows(), 'a.com', 'b.com')
    s = out['summary']
    # b.com is worse on risk_level, risk_score, high, secrets, active_findings
    assert s['b_worse'] >= 5
    assert s['a_worse'] == 0
    assert out['a']['slug'] == 'a.com' and out['b']['slug'] == 'b.com'
    assert out['b']['risk_level'] == 'High'


# ── guard ───────────────────────────────────────────────────────────────────────

def test_missing_slug_raises():
    with pytest.raises(ValueError):
        pc.compare_projects(_rows(), 'a.com', 'ghost.com')
    with pytest.raises(ValueError):
        pc.compare_projects(_rows(), 'ghost.com', 'b.com')


# ── thin loader over a real workspace ───────────────────────────────────────────

def _seed_project(base, slug_url, risk):
    from core.project import ProjectStore
    project = ProjectStore(base).get_or_create(slug_url)
    sid = '20260101_000000'
    scan_dir = project.start_scan(sid)
    report = {'scan_id': sid, 'finished_at': sid,
              'executive_summary': {'risk_level': 'High' if risk >= 50 else 'Low',
                                    'risk_score': risk, 'risk_100': risk,
                                    'metrics': {'risk_100': risk}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    project.record_scan(scan_dir, report)


def test_load_project_compare_over_workspace(tmp_path):
    _seed_project(str(tmp_path), 'https://low.com', 15)
    _seed_project(str(tmp_path), 'https://high.com', 65)
    out = pc.load_project_compare(str(tmp_path), 'low.com', 'high.com')
    rs = {m['key']: m for m in out['metrics']}['risk_score']
    assert rs['a'] == 15 and rs['b'] == 65
    assert rs['worse'] == 'b'


# ── CSV / Markdown renderers (shareable deliverable) ────────────────────────────

def _comparison():
    return pc.compare_projects(_rows(), 'a.com', 'b.com')


def test_render_csv_header_and_rows():
    import csv as _csv
    import io as _io
    text = pc.render_csv(_comparison())
    table = list(_csv.reader(_io.StringIO(text)))
    assert table[0] == ['Metric', 'a.com', 'b.com', 'Delta', 'Worse']
    rs = next(r for r in table if r[0] == 'Risk score')
    assert rs[1] == '20' and rs[2] == '70' and rs[3] == '+50' and rs[4] == 'b.com'


def test_render_markdown_has_title_summary_and_table():
    md = pc.render_markdown(_comparison())
    assert md.startswith('# Project comparison: a.com vs b.com')
    assert 'Worse metrics:' in md
    assert '| Metric | a.com | b.com | Δ | Worse |' in md
    assert '| Risk score | 20 | 70 | +50 | b.com |' in md
