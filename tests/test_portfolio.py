"""Tests for core.portfolio — cross-project executive aggregates (F5, T5.1).

Pure-function tests over hand-built metadata dicts (the shape
``ProjectStore.list_projects`` returns) plus a thin loader test against a real
projects tree on a tmp path. Offline, no Qt.
"""

import json

from core import portfolio
from core.executive_summary import RISK_COLORS


def _meta(slug, *, scans, url='https://x', updated_at='2026-01-01'):
    """A metadata.json dict like ProjectStore.list_projects yields."""
    return {'slug': slug, 'url': url, 'updated_at': updated_at,
            'scan_count': len(scans), 'scans': scans,
            'latest_scan': scans[-1] if scans else None}


def _scan(rid, *, risk='Low', score=2, surface=5, secrets=0, high=0, medium=0,
          source_map_leaks=0, weak_cookies=0, graphql=0, graphql_introspection=0):
    return {'id': rid, 'risk_level': risk, 'risk_score': score,
            'attack_surface_score': surface, 'secrets': secrets,
            'high': high, 'medium': medium,
            'source_map_leaks': source_map_leaks, 'weak_cookies': weak_cookies,
            'graphql': graphql, 'graphql_introspection': graphql_introspection}


# ── build_portfolio ──────────────────────────────────────────────────────────

def test_empty_portfolio():
    p = portfolio.build_portfolio([])
    assert p['rows'] == []
    assert p['totals']['projects'] == 0
    assert p['totals']['worst_risk_level'] is None


def test_row_pulls_latest_scan_metrics():
    meta = _meta('a.com', scans=[_scan('s1', risk='High', score=12,
                                       secrets=1, high=2, medium=3, surface=22)])
    row = portfolio.build_portfolio([meta])['rows'][0]
    assert row['slug'] == 'a.com'
    assert row['risk_level'] == 'High'
    assert row['risk_score'] == 12
    assert (row['secrets'], row['high'], row['medium']) == (1, 2, 3)
    assert row['attack_surface'] == 22
    assert row['scan_count'] == 1


def test_risk_delta_needs_two_scans():
    one = _meta('one', scans=[_scan('s1', score=5)])
    assert portfolio.build_portfolio([one])['rows'][0]['risk_delta'] is None

    two = _meta('two', scans=[_scan('s1', score=5), _scan('s2', score=8)])
    assert portfolio.build_portfolio([two])['rows'][0]['risk_delta'] == 3

    down = _meta('d', scans=[_scan('s1', score=8), _scan('s2', score=3)])
    assert portfolio.build_portfolio([down])['rows'][0]['risk_delta'] == -5


def test_risk_trend_direction_over_history():
    # risk_trend is the whole-history direction (vs risk_delta = latest-vs-prev).
    up = _meta('u', scans=[_scan('s1', score=2), _scan('s2', score=5),
                           _scan('s3', score=20)])
    assert portfolio.build_portfolio([up])['rows'][0]['risk_trend'] == 'up'
    down = _meta('d', scans=[_scan('s1', score=30), _scan('s2', score=4)])
    assert portfolio.build_portfolio([down])['rows'][0]['risk_trend'] == 'down'
    one = _meta('o', scans=[_scan('s1', score=5)])
    assert portfolio.build_portfolio([one])['rows'][0]['risk_trend'] == 'flat'


def test_active_findings_merged_by_slug():
    meta = _meta('a.com', scans=[_scan('s1')])
    p = portfolio.build_portfolio([meta], {'a.com': 7, 'other': 99})
    assert p['rows'][0]['active_findings'] == 7
    assert p['totals']['active_findings'] == 7


def test_rows_sorted_worst_risk_first():
    metas = [
        _meta('low', scans=[_scan('s', score=2)]),
        _meta('crit', scans=[_scan('s', score=40)]),
        _meta('mid', scans=[_scan('s', score=10)]),
    ]
    slugs = [r['slug'] for r in portfolio.build_portfolio(metas)['rows']]
    assert slugs == ['crit', 'mid', 'low']


def test_totals_worst_level_and_sums():
    metas = [
        _meta('a', scans=[_scan('s', risk='Medium', score=5,
                                secrets=1, high=0, medium=2)]),
        _meta('b', scans=[_scan('s', risk='Critical', score=30,
                                secrets=2, high=3, medium=1)]),
    ]
    totals = portfolio.build_portfolio(metas)['totals']
    assert totals['projects'] == 2
    assert totals['worst_risk_level'] == 'Critical'
    assert totals['worst_risk_color'] == RISK_COLORS['Critical']
    assert totals['secrets'] == 3
    assert totals['high'] == 3
    assert totals['medium'] == 3


def test_handles_never_scanned_project():
    meta = _meta('fresh', scans=[])
    row = portfolio.build_portfolio([meta])['rows'][0]
    assert row['risk_level'] is None
    assert row['risk_score'] is None
    assert row['risk_delta'] is None
    assert row['secrets'] == 0


# ── build_exposure_matrix ────────────────────────────────────────────────────

def test_exposure_matrix_shape():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', secrets=0, high=0, medium=0, surface=0)])]
    )['rows']
    m = portfolio.build_exposure_matrix(rows)
    assert m['col_labels'] == ['Secrets', 'SourceMap', 'Cookie', 'GraphQL',
                               'High', 'Medium', 'Surface', 'Findings']
    assert m['row_labels'] == ['a']
    assert len(m['cells']) == 1
    assert len(m['cells'][0]) == len(m['col_labels'])


def _cell(matrix, col_label):
    """The first row's cell under a given column label."""
    idx = matrix['col_labels'].index(col_label)
    return matrix['cells'][0][idx]


def test_exposure_sourcemap_leak_weighs_like_secret():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', source_map_leaks=3)])])['rows']
    text, color = _cell(portfolio.build_exposure_matrix(rows), 'SourceMap')
    assert text == '3'
    assert color == portfolio._HEAT_PALETTE[4]


def test_exposure_weak_cookies_is_moderate():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', weak_cookies=1)])])['rows']
    text, color = _cell(portfolio.build_exposure_matrix(rows), 'Cookie')
    assert text == '1'
    assert color == portfolio._HEAT_PALETTE[2]


def test_exposure_graphql_introspection_is_critical():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', graphql=2, graphql_introspection=1)])])['rows']
    text, color = _cell(portfolio.build_exposure_matrix(rows), 'GraphQL')
    assert text == '2'                                   # endpoint count shown
    assert color == portfolio._HEAT_PALETTE[4]           # introspection → critical


def test_exposure_graphql_reachable_without_introspection_is_moderate():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', graphql=1)])])['rows']
    _, color = _cell(portfolio.build_exposure_matrix(rows), 'GraphQL')
    assert color == portfolio._HEAT_PALETTE[2]


def test_exposure_pre_f5_metadata_degrades_to_clean(tmp_path):
    """A scan entry without the F5 breakdown keys → clean detection cells."""
    legacy = {'id': 's', 'risk_level': 'Low', 'risk_score': 2,
              'attack_surface_score': 0, 'secrets': 0, 'high': 0, 'medium': 0}
    rows = portfolio.build_portfolio([_meta('a', scans=[legacy])])['rows']
    m = portfolio.build_exposure_matrix(rows)
    for label in ('SourceMap', 'Cookie', 'GraphQL'):
        text, color = _cell(m, label)
        assert (text, color) == ('0', portfolio._HEAT_PALETTE[0])


def test_exposure_any_secret_is_critical_colour():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', secrets=1)])]
    )['rows']
    m = portfolio.build_exposure_matrix(rows)
    text, color = m['cells'][0][0]          # Secrets column
    assert text == '1'
    assert color == portfolio._HEAT_PALETTE[4]


def test_exposure_clean_is_green():
    rows = portfolio.build_portfolio(
        [_meta('a', scans=[_scan('s', secrets=0, high=0, medium=0, surface=0)])],
        {'a': 0},
    )['rows']
    cells = portfolio.build_exposure_matrix(rows)['cells'][0]
    assert all(color == portfolio._HEAT_PALETTE[0] for _, color in cells)


# ── load_portfolio (thin loader) ─────────────────────────────────────────────

def test_load_portfolio_reads_a_projects_tree(tmp_path):
    base = tmp_path
    proj_dir = base / 'Projects' / 'site.com'
    proj_dir.mkdir(parents=True)
    meta = _meta('site.com', scans=[_scan('s1', risk='High', score=12, secrets=1)])
    (proj_dir / 'metadata.json').write_text(json.dumps(meta), encoding='utf-8')

    p = portfolio.load_portfolio(str(base))
    assert p['totals']['projects'] == 1
    assert p['rows'][0]['slug'] == 'site.com'
    assert p['rows'][0]['risk_level'] == 'High'


def test_load_portfolio_empty_base(tmp_path):
    p = portfolio.load_portfolio(str(tmp_path))
    assert p['rows'] == []
