"""Tests for core.dashboard_charts — offline SVG chart fragments (F5, T5.2).

We assert on the *structure* of the returned SVG (it is pure data), never on
pixels: a valid <svg> root, the expected primitives, sane scaling and graceful
empty-states. No Qt, no network.
"""

import re

from core import dashboard_charts as dc


# ── sparkline ────────────────────────────────────────────────────────────────

def test_sparkline_empty_returns_note():
    svg = dc.sparkline([], empty_note='пусто')
    assert svg.startswith('<svg')
    assert 'пусто' in svg
    assert 'polyline' not in svg


def test_sparkline_all_none_is_empty():
    assert 'нет данных' in dc.sparkline([None, None])


def test_sparkline_single_point_is_a_dot():
    svg = dc.sparkline([5])
    assert '<circle' in svg
    assert 'polyline' not in svg


def test_sparkline_draws_polyline_with_one_point_per_value():
    svg = dc.sparkline([1, 2, 3, 4], width=240, height=48)
    assert svg.startswith('<svg') and svg.endswith('</svg>')
    m = re.search(r'<polyline points="([^"]+)"', svg)
    assert m
    pts = m.group(1).split()
    assert len(pts) == 4
    # End marker dot present.
    assert '<circle' in svg


def test_sparkline_skips_none_gaps():
    # Two real points → a 2-vertex polyline, regardless of the None gap.
    svg = dc.sparkline([1, None, 3])
    pts = re.search(r'<polyline points="([^"]+)"', svg).group(1).split()
    assert len(pts) == 2


def test_sparkline_flat_series_sits_on_midline():
    svg = dc.sparkline([7, 7, 7], width=100, height=50)
    ys = [float(p.split(',')[1])
          for p in re.search(r'<polyline points="([^"]+)"', svg).group(1).split()]
    # All equal → every point on the vertical mid-line.
    assert len(set(round(y, 1) for y in ys)) == 1
    assert abs(ys[0] - 25.0) < 1.0


def test_sparkline_higher_value_is_higher_on_screen():
    # SVG y grows downward, so the max value must have the smallest y.
    svg = dc.sparkline([0, 10], height=50)
    p0, p1 = re.search(r'<polyline points="([^"]+)"', svg).group(1).split()
    y0, y1 = float(p0.split(',')[1]), float(p1.split(',')[1])
    assert y1 < y0


# ── heatmap ──────────────────────────────────────────────────────────────────

def test_heatmap_empty_returns_note():
    assert 'нет данных' in dc.heatmap([], ['A'], [])
    assert 'нет данных' in dc.heatmap(['r'], [], [])


def test_heatmap_renders_a_rect_and_text_per_cell():
    rows = ['proj-a', 'proj-b']
    cols = ['Secrets', 'High']
    cells = [[('1', '#c62828'), ('0', '#2e7d32')],
             [('2', '#c62828'), ('3', '#ef6c00')]]
    svg = dc.heatmap(rows, cols, cells)
    assert svg.startswith('<svg') and svg.endswith('</svg>')
    assert svg.count('<rect') == 4          # one per cell
    # Cell colours are passed straight through.
    assert svg.count('#c62828') == 2
    assert '#ef6c00' in svg
    # Row + column labels present.
    for label in (*rows, *cols):
        assert label in svg


def test_heatmap_truncates_a_long_row_label():
    long = 'x' * 40
    svg = dc.heatmap([long], ['C'], [[('1', '#999')]])
    assert '…' in svg
    assert long not in svg


def test_heatmap_tolerates_short_rows():
    # A row with fewer cells than columns falls back to an empty grey cell.
    svg = dc.heatmap(['r'], ['A', 'B'], [[('1', '#111')]])
    assert svg.count('<rect') == 2


def test_heatmap_label_colors_default_light():
    svg = dc.heatmap(['proj'], ['Col'], [[('1', '#111')]])
    assert 'fill="#333333"' in svg          # row label
    assert 'fill="#444444"' in svg          # column header


def test_heatmap_label_colors_overridable_for_dark():
    svg = dc.heatmap(['proj'], ['Col'], [[('1', '#111')]],
                     label_color='#d4d4d4', header_color='#9aa0a6')
    assert 'fill="#d4d4d4"' in svg
    assert 'fill="#9aa0a6"' in svg
    assert 'fill="#333333"' not in svg
