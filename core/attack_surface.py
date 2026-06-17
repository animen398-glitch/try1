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
import re
from typing import Dict, List, Optional, Tuple

# Category -> colour (shared palette with the other report visuals).
_CATEGORY_COLORS = {
    'Technologies': '#1565c0',
    'Secrets': '#c62828',
    'Pages': '#2e7d32',
    'Findings': '#f9a825',
    'Infrastructure': '#6a1b9a',
    'Subdomains': '#00838f',
    'Endpoints': '#5d4037',
    'APIs': '#00695c',
    'Historical': '#827717',
    'Source Maps': '#ad1457',
    'GraphQL': '#512da8',
    'Weak Cookies': '#ef6c00',
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
    cookies = data('cookies')
    security = data('security')
    katana = data('katana')
    openapi = data('openapi')
    historical = data('historical')
    subdomains = data('subdomains')
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

    # Technologies: CMS/stack signatures plus the advanced fingerprint (with
    # version where known), de-duplicated by display label.
    tech_items: List[str] = list(recon.get('cms') or [])
    for t in recon.get('technologies') or []:
        if not isinstance(t, dict):
            continue
        name = t.get('name')
        if not name:
            continue
        label = f"{name} {t['version']}" if t.get('version') else name
        if label not in tech_items:
            tech_items.append(label)

    # Infrastructure: the Domain → ASN → IP → Provider chain (ip + ASN + provider).
    infra = recon.get('infrastructure') if isinstance(recon.get('infrastructure'), dict) else {}
    infra_items: List[str] = []
    if recon.get('ip'):
        infra_items.append(str(recon['ip']))
    if infra.get('asn'):
        infra_items.append(f"{infra['asn']} {infra.get('asn_name', '')}".strip())
    if infra.get('provider'):
        infra_items.append(str(infra['provider']))

    # Subdomains: the enumerated hosts (present only when the opt-in phase ran).
    sub_results = subdomains.get('results') if isinstance(
        subdomains.get('results'), list) else []
    sub_items = [e.get('subdomain', '') for e in sub_results
                 if isinstance(e, dict)]

    # APIs: discovered OpenAPI endpoints ("METHOD /path"), opt-in phase only.
    api_endpoints = openapi.get('endpoints') if isinstance(
        openapi.get('endpoints'), list) else []
    api_items = [f"{e.get('method', '')} {e.get('path', '')}".strip()
                 for e in api_endpoints if isinstance(e, dict)]

    # Historical: the interesting archived URLs (admin/auth/api/config subset).
    hist_items = historical.get('interesting') if isinstance(
        historical.get('interesting'), list) else []

    # Source Maps: the served .map files that leaked original source
    # (has_content) — the risk-bearing subset the risk engine also counts.
    smaps = security.get('source_maps') if isinstance(
        security.get('source_maps'), list) else []
    smap_items = [m.get('url', '') for m in smaps
                  if isinstance(m, dict) and m.get('has_content')]

    # Weak Cookies: the Set-Cookie entries the Cookie Audit scored Weak (missing
    # Secure/HttpOnly/SameSite) — the risk-bearing subset the risk engine counts;
    # strong/moderate cookies are not attack surface and stay off the graph.
    cookie_list = cookies.get('cookies') if isinstance(
        cookies.get('cookies'), list) else []
    cookie_items = [str(c.get('name', '')) for c in cookie_list
                    if isinstance(c, dict) and c.get('verdict') == 'Weak']

    # GraphQL: reachable endpoints (introspection ones are flagged in the
    # tooltip) — exposed query surface, opt-in security phase only.
    gql = security.get('graphql') if isinstance(
        security.get('graphql'), list) else []
    gql_items = [str(g.get('url', '')) + (' [introspection]'
                 if g.get('introspection') else '')
                 for g in gql if isinstance(g, dict) and g.get('graphql')]

    candidates = [
        _category('Technologies', tech_items),
        _category('Infrastructure', infra_items),
        _category('Secrets', secret_items),
        _category('Subdomains', sub_items),
        _category('Endpoints', katana.get('endpoints') or []),
        _category('APIs', api_items),
        _category('Historical', hist_items),
        _category('Source Maps', smap_items),
        _category('GraphQL', gql_items),
        _category('Weak Cookies', cookie_items),
        _category('Pages', page_items),
        # Findings excludes the source-map / GraphQL / weak-cookie findings:
        # those exposures are their own categories above (Source Maps / GraphQL
        # from the security phase, Weak Cookies from the cookie phase), so
        # counting them here too would double them in the surface score.
        _category('Findings', [f.get('title', '') for f in findings
                               if isinstance(f, dict)
                               and f.get('category')
                               not in ('sourcemap', 'graphql', 'cookie')]),
    ]
    return {'domain': str(domain),
            'categories': [c for c in candidates if c]}


# Per-category weight for the Attack Surface Score — risk-bearing categories
# (secrets, findings, source maps, GraphQL, weak cookies) count for more than
# mere breadth (pages/tech).
_SCORE_WEIGHTS = {
    'Secrets': 5, 'Source Maps': 3, 'Findings': 3, 'GraphQL': 3,
    'Weak Cookies': 2,
    'Endpoints': 2, 'APIs': 2, 'Historical': 2, 'Subdomains': 2,
    'Technologies': 1, 'Infrastructure': 1, 'Pages': 1,
}


def surface_score(surface: Dict) -> int:
    """Weighted breadth-of-exposure score from a built surface dict.

    Sums ``weight × category count`` so a wide surface with secrets/findings
    scores higher than one that only exposes a couple of technologies. Pure and
    deterministic — feeds the Dashboard 'Attack Surface Score' card."""
    total = 0
    for cat in surface.get('categories', []):
        total += _SCORE_WEIGHTS.get(cat.get('name'), 1) * int(cat.get('count', 0))
    return total


def score_band(score: int) -> str:
    """Bucket a surface score into a coarse label for display."""
    if score >= 40:
        return 'Critical'
    if score >= 20:
        return 'High'
    if score >= 8:
        return 'Medium'
    if score >= 1:
        return 'Low'
    return 'Minimal'


def _node_rect(cx: float, cy: float, label: str, color: str,
               title: str = '', text_color: str = '#fff', cls: str = '') -> str:
    e = html.escape
    width = max(86, len(label) * 7 + 20)
    height = 30
    x = cx - width / 2
    y = cy - height / 2
    tip = f'<title>{e(title)}</title>' if title else ''
    group_cls = f' class="{cls}"' if cls else ''
    return (
        f'<g{group_cls}>{tip}'
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height}" '
        f'rx="6" fill="{color}"/>'
        f'<text x="{cx:.1f}" y="{cy + 4:.1f}" text-anchor="middle" '
        f'font-size="12" fill="{text_color}" '
        f'font-family="Segoe UI,Roboto,sans-serif">{e(label)}</text>'
        f'</g>'
    )


# Layout constants shared by the static and interactive renderers.
_W, _H, _RADIUS = 760, 440, 150


def _layout(categories: List[Dict]) -> List[Tuple[Dict, float, float]]:
    """Place each category node radially around the centre (top, clockwise).

    Shared by ``render_svg`` and ``render_interactive`` so both renderers draw
    the identical hub-and-spoke geometry (single source — invariant I3)."""
    cx, cy = _W / 2, _H / 2
    n = len(categories) or 1
    out: List[Tuple[Dict, float, float]] = []
    for i, cat in enumerate(categories):
        theta = math.radians(-90 + i * (360 / n))
        out.append((cat, cx + _RADIUS * math.cos(theta),
                    cy + _RADIUS * math.sin(theta)))
    return out


def _slug(name: str) -> str:
    """Stable element-id slug for a category name ('Source Maps' → 'source-maps')."""
    return re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or 'cat'


def render_svg(surface: Dict) -> str:
    """Render the attack surface as a self-contained inline-SVG fragment."""
    categories = surface.get('categories', [])
    domain = surface.get('domain', 'target')
    if not categories:
        return ('<p style="font-size:13px;color:#999;">'
                'Недостаточно данных для графа атак-поверхности.</p>')

    cx, cy = _W / 2, _H / 2
    lines, nodes = [], []
    for cat, x, y in _layout(categories):
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
        f'<svg viewBox="0 0 {_W} {_H}" width="100%" '
        f'style="max-width:{_W}px;height:auto;" role="img" '
        f'aria-label="Attack surface graph">'
        f'{"".join(lines)}{"".join(nodes)}{centre}'
        f'</svg>'
    )


# Scoped CSS for the interactive graph: all selectors are namespaced under
# ``.as-wrap`` so the block never leaks into the rest of the report. No JS — the
# interactivity is pure CSS (``:hover`` highlight + ``:target`` click-to-open),
# so the report stays self-contained and offline (invariants I1/I2).
_INTERACTIVE_CSS = (
    '.as-wrap a{cursor:pointer;}'
    '.as-wrap .as-node rect{transition:stroke .1s,opacity .1s;}'
    '.as-wrap a:hover .as-node rect{stroke:#222;stroke-width:2.5;}'
    '.as-wrap a:hover .as-node text{font-weight:bold;}'
    '.as-wrap .as-panels{margin-top:10px;}'
    '.as-wrap .as-hint{font-size:12px;color:#888;margin:6px 0;}'
    '.as-wrap .as-panel{display:none;margin:6px 0;padding:8px 12px;'
    'background:#fafafa;border-radius:4px;font-size:13px;}'
    '.as-wrap .as-panel:target{display:block;}'
    '.as-wrap .as-panel ul{margin:6px 0 0;padding-left:20px;}'
    '.as-wrap .as-panel li{margin:2px 0;word-break:break-all;}'
)


def render_interactive(surface: Dict) -> str:
    """Render the attack surface as an offline *interactive* fragment.

    Same hub-and-spoke SVG as ``render_svg``, but each category node is a link
    to its detail panel: clicking a node opens that category's full item list
    via the CSS ``:target`` pseudo-class, and hovering highlights the node — all
    with zero JavaScript and no external resource, so the offline report
    contract holds (invariant I2). This is the audit-approved offline form of
    the "interactive Attack Surface Graph" (the CDN/JS-library version was
    rejected for breaking that contract).
    """
    categories = surface.get('categories', [])
    domain = surface.get('domain', 'target')
    if not categories:
        return ('<p style="font-size:13px;color:#999;">'
                'Недостаточно данных для графа атак-поверхности.</p>')

    e = html.escape
    cx, cy = _W / 2, _H / 2
    lines, nodes, panels = [], [], []
    for cat, x, y in _layout(categories):
        slug = _slug(cat['name'])
        lines.append(
            f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{x:.1f}" y2="{y:.1f}" '
            f'stroke="#ccc" stroke-width="1.5"/>'
        )
        label = f"{cat['name']} ({cat['count']})"
        tooltip = '\n'.join(cat['items'])
        node = _node_rect(x, y, label, cat['color'], tooltip, cls='as-node')
        # SVG2 <a href> — internal fragment only, so no external resource.
        nodes.append(f'<a href="#as-{slug}">{node}</a>')

        shown = cat['items']
        items_html = ''.join(f'<li>{e(str(it))}</li>' for it in shown)
        extra = cat['count'] - len(shown)
        if extra > 0:
            items_html += f'<li style="color:#888;">… ещё {extra}</li>'
        panels.append(
            f'<div class="as-panel" id="as-{slug}" '
            f'style="border-left:4px solid {cat["color"]};">'
            f'<b>{e(cat["name"])}</b> ({cat["count"]})'
            f'<ul>{items_html}</ul></div>'
        )

    centre = _node_rect(cx, cy, domain, '#222')
    svg = (
        f'<svg viewBox="0 0 {_W} {_H}" width="100%" '
        f'style="max-width:{_W}px;height:auto;" role="img" '
        f'aria-label="Attack surface graph">'
        f'{"".join(lines)}{"".join(nodes)}{centre}'
        f'</svg>'
    )
    return (
        f'<div class="as-wrap"><style>{_INTERACTIVE_CSS}</style>{svg}'
        f'<div class="as-panels">'
        f'<p class="as-hint">Кликните узел категории, чтобы увидеть элементы.</p>'
        f'{"".join(panels)}</div></div>'
    )
