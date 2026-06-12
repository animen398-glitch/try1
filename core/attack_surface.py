"""core/attack_surface.py
Static, offline Attack Surface graph for the collection report.

Renders the domain at the centre with a spoke to each discovered category
(Technologies, Secrets, Pages, Findings, Infrastructure…), every category node
carrying a count and — via an SVG ``<title>`` — the list of items on hover.

Pure / stdlib-only and self-contained (architectural invariants I1/I2): the
graph is inline ``<svg>`` with no JavaScript and no external resource, so it
embeds straight into the offline report. This is the audit-approved static
form of the "Attack Surface Graph" candidate — the interactive JS-library
version was rejected for breaking the offline contract.

``build_surface`` reads a collection ``report`` dict, but only includes
categories that actually have data, so a partial run degrades to a smaller
graph rather than inventing nodes.
"""

import html
import math
from typing import Dict, List, Optional

# Category -> colour (shared palette with the other report visuals).
_CATEGORY_COLORS = {
    'Technologies': '#1565c0',
    'Secrets': '#c62828',
    'Pages': '#2e7d32',
    'Findings': '#f9a825',
    'Infrastructure': '#6a1b9a',
    'Subdomains': '#00838f',
    'Endpoints': '#5d4037',
    'Source Maps': '#ad1457',
}
_DEFAULT_COLOR = '#555'
_MAX_ITEMS = 10            # items kept per category (for the hover tooltip)


def _category(name: str, items: List[str]) -> Optional[Dict]:
    items = [str(i) for i in items if i not in (None, '', [])]
    if not items:
        return None
    return {
        'name': name,
        'color': _CATEGORY_COLORS.get(name, _DEFAULT_COLOR),
        'count': len(items),
        'items': items[:_MAX_ITEMS],
    }


def build_surface(report: Dict) -> Dict:
    """Extract attack-surface categories from a collection ``report``.

    Returns ``{'domain': str, 'categories': [ {name,color,count,items}, … ]}``
    with empty categories omitted.
    """
    phases = report.get('phases', {})

    def data(name: str) -> Dict:
        phase = phases.get(name, {})
        d = phase.get('data', {}) if isinstance(phase, dict) else {}
        return d if isinstance(d, dict) else {}

    recon = data('recon')
    api = data('api')
    capture = data('capture')
    katana = data('katana')
    vulns = phases.get('vulns', {})
    findings = vulns.get('findings', []) if isinstance(vulns, dict) else []

    domain = report.get('domain') or report.get('url') or 'target'

    # Secrets: surface the secret *types* found (api_key_extractor.details maps
    # type -> [matches]); fall back to a count when only a number is present.
    secret_details = api.get('details') if isinstance(api.get('details'), dict) else {}
    secret_items = list(secret_details.keys())
    if not secret_items and api.get('keys_found'):
        secret_items = [f"{api['keys_found']} keys"]

    pages = capture.get('site_map') or []
    page_items = [p.get('url', '') for p in pages if isinstance(p, dict)]

    candidates = [
        _category('Technologies', recon.get('cms') or []),
        _category('Infrastructure',
                  [recon['ip']] if recon.get('ip') else []),
        _category('Secrets', secret_items),
        _category('Endpoints', katana.get('endpoints') or []),
        _category('Pages', page_items),
        _category('Findings', [f.get('title', '') for f in findings]),
    ]
    return {'domain': str(domain),
            'categories': [c for c in candidates if c]}


def _node_rect(cx: float, cy: float, label: str, color: str,
               title: str = '', text_color: str = '#fff') -> str:
    e = html.escape
    width = max(86, len(label) * 7 + 20)
    height = 30
    x = cx - width / 2
    y = cy - height / 2
    tip = f'<title>{e(title)}</title>' if title else ''
    return (
        f'<g>{tip}'
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height}" '
        f'rx="6" fill="{color}"/>'
        f'<text x="{cx:.1f}" y="{cy + 4:.1f}" text-anchor="middle" '
        f'font-size="12" fill="{text_color}" '
        f'font-family="Segoe UI,Roboto,sans-serif">{e(label)}</text>'
        f'</g>'
    )


def render_svg(surface: Dict) -> str:
    """Render the attack surface as a self-contained inline-SVG fragment."""
    categories = surface.get('categories', [])
    domain = surface.get('domain', 'target')
    if not categories:
        return ('<p style="font-size:13px;color:#999;">'
                'Недостаточно данных для графа атак-поверхности.</p>')

    width, height = 760, 440
    cx, cy = width / 2, height / 2
    radius = 150

    lines, nodes = [], []
    n = len(categories)
    for i, cat in enumerate(categories):
        # Start at the top (-90°) and go clockwise.
        theta = math.radians(-90 + i * (360 / n))
        x = cx + radius * math.cos(theta)
        y = cy + radius * math.sin(theta)
        lines.append(
            f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{x:.1f}" y2="{y:.1f}" '
            f'stroke="#ccc" stroke-width="1.5"/>'
        )
        label = f"{cat['name']} ({cat['count']})"
        tooltip = '\n'.join(cat['items'])
        nodes.append(_node_rect(x, y, label, cat['color'], tooltip))

    centre = _node_rect(cx, cy, domain, '#222')

    # No xmlns: inline SVG in the HTML5 report renders without it, and omitting
    # it keeps the offline report free of any external-looking URL string.
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'style="max-width:{width}px;height:auto;" role="img" '
        f'aria-label="Attack surface graph">'
        f'{"".join(lines)}{"".join(nodes)}{centre}'
        f'</svg>'
    )
