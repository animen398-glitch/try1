"""core/report_charts.py
Offline, dependency-free chart fragments for HTML reports.

Pure stdlib and self-contained (architectural invariants I1/I2): charts are
plain ``<div>`` boxes with inline CSS — no JavaScript, no charting library, no
external resource — so they render in the offline report exactly like the rest
of it. This is the "Reporting 2.0 / visual metrics" building block, the
offline-safe answer to the rejected matplotlib/QtCharts approach.
"""

import html
from typing import List, Tuple

# (label, value, colour)
Segment = Tuple[str, float, str]


def _fmt(value: float) -> str:
    v = float(value)
    return str(int(v)) if v.is_integer() else f'{v:.1f}'


def stacked_bar(segments: List[Segment], *, height: int = 18,
                legend: bool = True, empty_note: str = 'нет данных') -> str:
    """A single stacked horizontal bar from ``segments``.

    Zero/negative segments are skipped; an all-empty input yields a small note.
    Widths are percentages of the total, so the bar always fills its container.
    """
    e = html.escape
    total = sum(max(0.0, v) for _, v, _ in segments)
    if total <= 0:
        return f'<p style="font-size:12px;color:#999;margin:4px 0;">{e(empty_note)}</p>'

    cells = []
    for label, value, color in segments:
        v = max(0.0, float(value))
        if v <= 0:
            continue
        pct = v / total * 100.0
        cells.append(
            f'<div title="{e(label)}: {e(_fmt(value))}" style="width:{pct:.2f}%;'
            f'background:{color};height:{height}px;"></div>'
        )
    bar = (f'<div style="display:flex;width:100%;border-radius:4px;'
           f'overflow:hidden;background:#eee;">{"".join(cells)}</div>')
    if not legend:
        return bar

    chips = ''.join(
        f'<span style="font-size:11px;margin-right:10px;white-space:nowrap;">'
        f'<span style="display:inline-block;width:9px;height:9px;background:{color};'
        f'border-radius:2px;margin-right:3px;"></span>'
        f'{e(label)}: <b>{e(_fmt(value))}</b></span>'
        for label, value, color in segments if float(value) > 0
    )
    return f'{bar}<div style="margin-top:4px;line-height:1.6;">{chips}</div>'
