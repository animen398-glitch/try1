"""core/dashboard_charts.py
Offline, dependency-free SVG chart fragments for the Executive Dashboard (F5).

The sibling of ``core/report_charts.py``: pure stdlib, self-contained, no
JavaScript and no charting library (architectural invariants I1/I2). Each helper
returns a single ``<svg>`` string that renders identically in an offline HTML
report and in the GUI via Qt's ``QSvgWidget`` — so the dashboard adds zero
runtime dependencies and does not inflate the ``.exe`` (the project's standing
decision against matplotlib/QtCharts/QWebEngine).

These are purely presentational: callers supply already-aggregated numbers and,
for the heatmap, the per-cell colours. The value→colour mapping is a data
concern and lives in ``core/portfolio.py`` (kept testable, away from Qt).
"""

import html
from typing import Optional, Sequence, Tuple

# One heatmap cell: (display text, fill colour).
Cell = Tuple[str, str]


def _empty(note: str) -> str:
    e = html.escape
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="24">'
            f'<text x="0" y="16" font-family="sans-serif" font-size="12" '
            f'fill="#999">{e(note)}</text></svg>')


def sparkline(values: Sequence[Optional[float]], *, width: int = 240,
              height: int = 48, color: str = '#0078d4', fill: bool = True,
              empty_note: str = 'нет данных') -> str:
    """A compact trend line over ``values`` (a numeric series, oldest→newest).

    ``None`` entries are treated as gaps and dropped. An empty/all-None series
    yields a small note; a single point is drawn as a dot. The line is scaled to
    the series' own min/max, so a flat series sits on the mid-line rather than
    collapsing to an edge.
    """
    nums = [float(v) for v in values if v is not None]
    if not nums:
        return _empty(empty_note)

    pad = 4.0
    x0, x1 = pad, width - pad
    y0, y1 = pad, height - pad
    n = len(nums)
    vmin, vmax = min(nums), max(nums)
    span = vmax - vmin

    def _x(i: int) -> float:
        return x0 if n == 1 else x0 + (x1 - x0) * i / (n - 1)

    def _y(v: float) -> float:
        if span == 0:
            return (y0 + y1) / 2.0
        return y1 - (v - vmin) / span * (y1 - y0)

    pts = [(_x(i), _y(v)) for i, v in enumerate(nums)]
    pts_str = ' '.join(f'{x:.1f},{y:.1f}' for x, y in pts)

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
             f'height="{height}" viewBox="0 0 {width} {height}">']
    if fill and n > 1:
        area = f'{x0:.1f},{y1:.1f} {pts_str} {x1:.1f},{y1:.1f}'
        parts.append(f'<polygon points="{area}" fill="{color}" '
                     f'fill-opacity="0.15"/>')
    if n == 1:
        x, y = pts[0]
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}"/>')
    else:
        parts.append(f'<polyline points="{pts_str}" fill="none" '
                     f'stroke="{color}" stroke-width="2" '
                     f'stroke-linejoin="round" stroke-linecap="round"/>')
        lx, ly = pts[-1]
        parts.append(f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="3" fill="{color}"/>')
    parts.append('</svg>')
    return ''.join(parts)


def heatmap(row_labels: Sequence[str], col_labels: Sequence[str],
            cells: Sequence[Sequence[Cell]], *, cell_w: int = 64,
            cell_h: int = 28, label_w: int = 170, header_h: int = 24,
            label_color: str = '#333333', header_color: str = '#444444',
            empty_note: str = 'нет данных') -> str:
    """A labelled grid heatmap: ``cells[r][c]`` is ``(text, fill_colour)``.

    Rows are labelled on the left (``row_labels``), columns across the top
    (``col_labels``). Cell colours are supplied by the caller — this only draws.
    ``label_color``/``header_color`` style the (transparent-background) row/column
    labels; their defaults suit a light background, callers on a dark theme pass
    light text (F6 T6.4). Cell text stays white over the coloured cells.
    """
    e = html.escape
    if not row_labels or not col_labels:
        return _empty(empty_note)

    ncols = len(col_labels)
    nrows = len(row_labels)
    width = label_w + cell_w * ncols
    height = header_h + cell_h * nrows

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
             f'height="{height}" viewBox="0 0 {width} {height}" '
             f'font-family="sans-serif">']

    # Column headers.
    for c, label in enumerate(col_labels):
        cx = label_w + cell_w * c + cell_w / 2
        parts.append(f'<text x="{cx:.1f}" y="{header_h - 7}" font-size="11" '
                     f'fill="{header_color}" text-anchor="middle">'
                     f'{e(str(label))}</text>')

    for r, rlabel in enumerate(row_labels):
        ry = header_h + cell_h * r
        # Row label (truncated to fit the label column).
        label = str(rlabel)
        if len(label) > 26:
            label = label[:25] + '…'
        parts.append(f'<text x="4" y="{ry + cell_h / 2 + 4:.1f}" font-size="12" '
                     f'fill="{label_color}">{e(label)}</text>')
        row = cells[r] if r < len(cells) else []
        for c in range(ncols):
            text, color = row[c] if c < len(row) else ('', '#eee')
            cx = label_w + cell_w * c
            parts.append(
                f'<rect x="{cx}" y="{ry}" width="{cell_w - 2}" '
                f'height="{cell_h - 2}" rx="3" fill="{color}"/>')
            parts.append(
                f'<text x="{cx + cell_w / 2:.1f}" y="{ry + cell_h / 2 + 4:.1f}" '
                f'font-size="12" fill="#fff" text-anchor="middle">'
                f'{e(str(text))}</text>')
    parts.append('</svg>')
    return ''.join(parts)
