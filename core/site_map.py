"""core/site_map.py
Build and render a visual site map from captured-page records.

Pure / stdlib-only and offline by design (architectural invariants I1/I2/I5):
it takes the list of page records that ``SiteContentCapture`` produces — each
``{'url': ..., 'status': <int|None>, 'file': ...}`` — and turns it into a
path-segment tree plus a self-contained, inline-CSS HTML fragment that embeds
straight into the offline collection report. No network, no third-party deps,
so it is trivially unit-testable.

Status colouring groups responses the way a tester reads a crawl:
    2xx ok · 3xx redirect · 4xx client-error · 5xx server-error · err (no reply)
"""

import html
from typing import Dict, List, Optional
from urllib.parse import urlparse

# (lo, hi, label, colour) — inclusive HTTP status ranges for display.
_STATUS_GROUPS = [
    (200, 299, '2xx', '#2e7d32'),   # ok        — green
    (300, 399, '3xx', '#1565c0'),   # redirect  — blue
    (400, 499, '4xx', '#c62828'),   # client err— red
    (500, 599, '5xx', '#6a1b9a'),   # server err— purple
]
_ERR_GROUP = 'err'
_ERR_COLOR = '#777'                 # no status (network error / timeout) — grey

# Stable order for legends / summaries.
GROUP_ORDER = ['2xx', '3xx', '4xx', '5xx', _ERR_GROUP]


def classify_status(status: Optional[int]) -> Dict[str, str]:
    """Map an HTTP status (or ``None``) to ``{'group', 'color'}`` for display."""
    if isinstance(status, int):
        for lo, hi, label, color in _STATUS_GROUPS:
            if lo <= status <= hi:
                return {'group': label, 'color': color}
    return {'group': _ERR_GROUP, 'color': _ERR_COLOR}


# Content-Type (MIME) → short response-type label for the site-map column.
_TYPE_LABELS = [
    ('html', 'html'), ('json', 'json'), ('javascript', 'js'), ('css', 'css'),
    ('xml', 'xml'), ('image/', 'image'), ('font', 'font'), ('pdf', 'pdf'),
    ('text/plain', 'text'),
]


def classify_type(content_type: Optional[str]) -> str:
    """Map a MIME type to a short response-type label (``html``/``json``/…)."""
    if not content_type:
        return ''
    ct = content_type.lower()
    for needle, label in _TYPE_LABELS:
        if needle in ct:
            return label
    return ct.split('/')[-1][:8]


def _new_node(segment: str, path: str) -> Dict:
    return {'segment': segment, 'path': path, 'status': None,
            'url': None, 'content_type': None, 'depth': 0, 'children': {}}


def build_tree(pages: List[Dict]) -> Dict:
    """Fold flat page records into a tree keyed by URL path segments.

    The returned root represents ``/``; ``children`` maps each path segment to a
    child node. A node's ``status``/``url`` are set when a crawled page lands at
    exactly that path (intermediate path nodes created only to host children
    keep ``status=None``). Order-independent and idempotent.
    """
    root = _new_node('/', '/')
    for p in pages:
        url = p.get('url') or ''
        status = p.get('status')
        path = urlparse(url).path or '/'
        segments = [s for s in path.split('/') if s]
        node = root
        acc = ''
        for depth, seg in enumerate(segments, start=1):
            acc = f'{acc}/{seg}'
            child = node['children'].get(seg)
            if child is None:
                child = _new_node(seg, acc)
                child['depth'] = depth
                node['children'][seg] = child
            node = child
        # Leaf (or root for '/') is the page itself.
        node['status'] = status
        node['url'] = url
        node['content_type'] = p.get('content_type')
    return root


def _page_depth(page: Dict) -> int:
    d = page.get('depth')
    if isinstance(d, int):
        return d
    return len([s for s in urlparse(page.get('url') or '').path.split('/') if s])


def summarize(pages: List[Dict]) -> Dict[str, int]:
    """Count pages per status group plus the total and the max crawl depth."""
    counts = {g: 0 for g in GROUP_ORDER}
    for p in pages:
        counts[classify_status(p.get('status'))['group']] += 1
    counts['total'] = len(pages)
    counts['max_depth'] = max((_page_depth(p) for p in pages), default=0)
    return counts


def _badge(status: Optional[int]) -> str:
    info = classify_status(status)
    label = str(status) if isinstance(status, int) else 'ERR'
    return (f'<span style="display:inline-block;min-width:34px;text-align:center;'
            f'font-size:11px;font-weight:bold;color:#fff;background:{info["color"]};'
            f'border-radius:4px;padding:1px 6px;margin-left:8px;">'
            f'{html.escape(label)}</span>')


def _type_chip(content_type: Optional[str]) -> str:
    label = classify_type(content_type)
    if not label:
        return ''
    return (f'<span style="display:inline-block;font-size:10px;color:#555;'
            f'background:#eef1f5;border-radius:4px;padding:0 5px;margin-left:6px;">'
            f'{html.escape(label)}</span>')


def _render_children(node: Dict) -> str:
    children = node['children']
    if not children:
        return ''
    items = []
    for seg in sorted(children):
        child = children[seg]
        is_page = child['url'] is not None
        badge = _badge(child['status']) if is_page else ''
        chip = _type_chip(child.get('content_type')) if is_page else ''
        items.append(
            f'<li style="margin:2px 0;">'
            f'<span style="font-family:Consolas,Menlo,monospace;">'
            f'{html.escape(seg)}</span>{badge}{chip}'
            f'{_render_children(child)}</li>'
        )
    return (f'<ul style="list-style:none;margin:0;padding-left:18px;'
            f'border-left:1px solid #eee;">{"".join(items)}</ul>')


def render_html(pages: List[Dict]) -> str:
    """Return a self-contained inline-CSS HTML fragment for the report.

    Renders a status legend with per-group counts and the path tree. Empty
    input yields a friendly placeholder rather than an empty block.
    """
    if not pages:
        return '<p style="font-size:13px;color:#999;">Нет захваченных страниц.</p>'

    counts = summarize(pages)

    def _group_color(group: str) -> str:
        if group == _ERR_GROUP:
            return _ERR_COLOR
        return next(c for _, _, label, c in _STATUS_GROUPS if label == group)

    # Visual status distribution bar (offline inline-CSS) + count chips.
    from core.report_charts import stacked_bar
    segments = [(group, counts.get(group, 0), _group_color(group))
                for group in GROUP_ORDER]
    legend = (f'<p style="margin:0 0 4px;font-size:12px;color:#666;">'
              f'Страниц всего: <b>{counts["total"]}</b> · '
              f'макс. глубина: <b>{counts.get("max_depth", 0)}</b></p>'
              + stacked_bar(segments))

    tree = build_tree(pages)
    root_badge = _badge(tree['status']) if tree['url'] is not None else ''
    root_chip = _type_chip(tree.get('content_type')) if tree['url'] is not None else ''
    body = (f'<div style="font-size:13px;"><span style='
            f'"font-family:Consolas,Menlo,monospace;font-weight:bold;">/</span>'
            f'{root_badge}{root_chip}{_render_children(tree)}</div>')
    return legend + body
