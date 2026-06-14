"""core/tech_fingerprint.py
Advanced, offline technology fingerprinting (Wappalyzer-style, stdlib only).

This complements — does not duplicate — recon_engine's existing frontend/CMS
signatures (React/Vue/Angular/WordPress/…). It adds the categories recon did
not cover and that are best read from the HTTP response rather than the HTML
body: CDN / infrastructure, web server, backend framework, language, and
analytics — plus **version extraction** where the response advertises it.

Pure and deterministic (architectural invariants I1/I5): a single
``fingerprint(headers, html, scripts)`` call returns a list of
``{name, category, version, evidence}`` with no network and no dependency, so
it is trivially testable and feeds the recon result → Attack Surface
"Technologies" → report.
"""

import html
import re
from typing import Dict, List, Optional

# Detection categories (display order in reports).
CATEGORY_ORDER = ['CDN', 'Server', 'Backend', 'JS Framework', 'Language',
                  'Analytics']

# A signature matches if ANY of its matchers fire. Matchers:
#   headers       {header: value-regex}   header present AND value matches
#   header_present[header, …]             header merely present
#   cookies       [substr, …]             substring in Set-Cookie
#   scripts       [substr, …]             substring in any <script src>
#   html          [regex, …]              regex search in the HTML body
#   version       {'header','regex'}       extract group(1) from a header value
#   version_html  {'regex'}               extract group(1) from the HTML body
_SIGNATURES: List[Dict] = [
    # ── CDN / Infrastructure (header-driven) ──────────────────────────────
    {'name': 'Cloudflare', 'category': 'CDN',
     'headers': {'server': r'cloudflare'},
     'header_present': ['cf-ray', 'cf-cache-status']},
    {'name': 'Akamai', 'category': 'CDN',
     'headers': {'server': r'akamai'},
     'header_present': ['x-akamai-transformed', 'akamai-grn']},
    {'name': 'Fastly', 'category': 'CDN',
     'headers': {'x-served-by': r'cache-', 'via': r'fastly'},
     'header_present': ['x-fastly-request-id', 'fastly-restarts']},
    {'name': 'Amazon CloudFront', 'category': 'CDN',
     'headers': {'via': r'cloudfront', 'server': r'cloudfront'},
     'header_present': ['x-amz-cf-id']},
    {'name': 'Vercel', 'category': 'CDN',
     'headers': {'server': r'vercel'},
     'header_present': ['x-vercel-id', 'x-vercel-cache']},
    {'name': 'Netlify', 'category': 'CDN',
     'headers': {'server': r'netlify'},
     'header_present': ['x-nf-request-id']},

    # ── Web server (with version) ─────────────────────────────────────────
    {'name': 'Nginx', 'category': 'Server',
     'headers': {'server': r'nginx'},
     'version': {'header': 'server', 'regex': r'nginx/([\d.]+)'}},
    {'name': 'Apache', 'category': 'Server',
     'headers': {'server': r'apache'},
     'version': {'header': 'server', 'regex': r'apache/([\d.]+)'}},
    {'name': 'Microsoft-IIS', 'category': 'Server',
     'headers': {'server': r'iis|microsoft-iis'},
     'version': {'header': 'server', 'regex': r'iis/([\d.]+)'}},
    {'name': 'LiteSpeed', 'category': 'Server',
     'headers': {'server': r'litespeed'}},
    {'name': 'Caddy', 'category': 'Server',
     'headers': {'server': r'caddy'}},

    # ── Backend frameworks (cookie / header) ──────────────────────────────
    {'name': 'Laravel', 'category': 'Backend',
     'cookies': ['laravel_session']},
    {'name': 'Django', 'category': 'Backend',
     'cookies': ['csrftoken', 'django_language']},
    {'name': 'Ruby on Rails', 'category': 'Backend',
     'cookies': ['_rails', '_session_id'],
     'header_present': ['x-runtime']},
    {'name': 'Express', 'category': 'Backend',
     'headers': {'x-powered-by': r'express'}},
    {'name': 'ASP.NET', 'category': 'Backend',
     'headers': {'x-powered-by': r'asp\.net'},
     'header_present': ['x-aspnet-version'],
     'version': {'header': 'x-aspnet-version', 'regex': r'([\d.]+)'}},
    {'name': 'Spring', 'category': 'Backend',
     'header_present': ['x-application-context']},
    {'name': 'Flask / Werkzeug', 'category': 'Backend',
     'headers': {'server': r'werkzeug'},
     'version': {'header': 'server', 'regex': r'werkzeug/([\d.]+)'}},

    # ── JS meta-frameworks (SSR/SSG — HTML markers, build paths, headers) ──
    # These complement recon's React/Vue detection: a SPA library plus the
    # meta-framework around it (Next on React, Nuxt on Vue, …). Versions are
    # rarely advertised, except Angular's ``ng-version`` (read from the body).
    {'name': 'Next.js', 'category': 'JS Framework',
     'headers': {'x-powered-by': r'next\.js'},
     'scripts': ['/_next/'],
     'html': [r'id=["\']__next["\']', r'__NEXT_DATA__']},
    {'name': 'Nuxt.js', 'category': 'JS Framework',
     'scripts': ['/_nuxt/'],
     'html': [r'id=["\']__nuxt["\']', r'window\.__NUXT__']},
    {'name': 'SvelteKit', 'category': 'JS Framework',
     'scripts': ['/_app/immutable/'],
     'html': [r'data-sveltekit', r'__sveltekit_']},
    {'name': 'Gatsby', 'category': 'JS Framework',
     'scripts': ['/page-data/'],
     'html': [r'id=["\']___gatsby["\']']},
    {'name': 'Remix', 'category': 'JS Framework',
     'html': [r'window\.__remixContext', r'__remixManifest']},
    {'name': 'Astro', 'category': 'JS Framework',
     'html': [r'<astro-island']},
    {'name': 'Angular', 'category': 'JS Framework',
     'html': [r'ng-version=["\'][\d.]+["\']', r'_nghost-'],
     'version_html': {'regex': r'ng-version=["\']([\d.]+)["\']'}},

    # ── Language (header) ─────────────────────────────────────────────────
    {'name': 'PHP', 'category': 'Language',
     'headers': {'x-powered-by': r'php'},
     'version': {'header': 'x-powered-by', 'regex': r'php/([\d.]+)'}},

    # ── Analytics / tag managers (scripts / inline) ───────────────────────
    {'name': 'Google Analytics', 'category': 'Analytics',
     'scripts': ['google-analytics.com/analytics.js', 'googletagmanager.com/gtag',
                 'gtag/js?id=g-'],
     'html': [r'gtag\(\s*[\'"]config', r'\bga\(\s*[\'"]create']},
    {'name': 'Google Tag Manager', 'category': 'Analytics',
     'scripts': ['googletagmanager.com/gtm.js'],
     'html': [r'GTM-[A-Z0-9]+']},
    {'name': 'Hotjar', 'category': 'Analytics',
     'scripts': ['static.hotjar.com', 'hotjar.com/c/hotjar'],
     'html': [r'\bhj\(', r'_hjSettings']},
    {'name': 'Mixpanel', 'category': 'Analytics',
     'scripts': ['cdn.mxpnl.com', 'mixpanel.com'],
     'html': [r'mixpanel\.init']},
    {'name': 'Segment', 'category': 'Analytics',
     'scripts': ['cdn.segment.com/analytics.js'],
     'html': [r'analytics\.load\(']},
    {'name': 'Amplitude', 'category': 'Analytics',
     'scripts': ['cdn.amplitude.com'],
     'html': [r'amplitude\.getInstance']},
    {'name': 'Facebook Pixel', 'category': 'Analytics',
     'scripts': ['connect.facebook.net'],
     'html': [r'fbq\(\s*[\'"]init']},
]


def _norm_headers(headers: Optional[Dict]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _extract_version(spec: Dict, headers: Dict[str, str]) -> Optional[str]:
    value = headers.get(spec.get('header', '').lower(), '')
    if not value:
        return None
    m = re.search(spec['regex'], value, re.IGNORECASE)
    return m.group(1) if m else None


def _match(sig: Dict, headers: Dict[str, str], set_cookie: str,
           html: str, scripts_blob: str):
    """Return (evidence, version) when the signature fires, else (None, None).

    Version is resolved the same way regardless of which matcher fired — from a
    response header (``version``) or the HTML body (``version_html``) — so e.g.
    Angular detected via an HTML marker still reports its ``ng-version``.
    """
    evidence = None
    # Header value regex.
    for hname, value_re in sig.get('headers', {}).items():
        value = headers.get(hname.lower())
        if value is not None and re.search(value_re, value, re.IGNORECASE):
            evidence = f'header:{hname}'
            break
    # Header merely present.
    if evidence is None:
        for hname in sig.get('header_present', []):
            if hname.lower() in headers:
                evidence = f'header:{hname}'
                break
    # Set-Cookie substring.
    if evidence is None:
        sc = set_cookie.lower()
        for needle in sig.get('cookies', []):
            if needle.lower() in sc:
                evidence = f'cookie:{needle}'
                break
    # <script src> substring.
    if evidence is None:
        for needle in sig.get('scripts', []):
            if needle.lower() in scripts_blob:
                evidence = f'script:{needle}'
                break
    # HTML regex.
    if evidence is None:
        for pattern in sig.get('html', []):
            if re.search(pattern, html, re.IGNORECASE):
                evidence = 'html'
                break
    if evidence is None:
        return None, None
    return evidence, _version(sig, headers, html)


def _version(sig: Dict, headers: Dict[str, str],
             html: str = '') -> Optional[str]:
    spec = sig.get('version')
    if spec:
        v = _extract_version(spec, headers)
        if v:
            return v
    hspec = sig.get('version_html')
    if hspec:
        m = re.search(hspec['regex'], html or '', re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def fingerprint(headers: Optional[Dict] = None, html: str = '',
                scripts: Optional[List[str]] = None) -> List[Dict]:
    """Detect technologies from an HTTP response.

    ``headers`` is the response header map (Set-Cookie included as 'set-cookie'),
    ``html`` the body, ``scripts`` the list of ``<script src>`` URLs. Returns a
    de-duplicated list of ``{name, category, version, evidence}`` ordered by
    CATEGORY_ORDER then name.
    """
    hmap = _norm_headers(headers)
    set_cookie = hmap.get('set-cookie', '')
    scripts_blob = '\n'.join(scripts or []).lower()

    found: Dict[str, Dict] = {}
    for sig in _SIGNATURES:
        evidence, version = _match(sig, hmap, set_cookie, html or '', scripts_blob)
        if evidence and sig['name'] not in found:
            found[sig['name']] = {
                'name': sig['name'], 'category': sig['category'],
                'version': version, 'evidence': evidence,
            }

    def sort_key(t: Dict):
        cat = t['category']
        idx = CATEGORY_ORDER.index(cat) if cat in CATEGORY_ORDER else len(CATEGORY_ORDER)
        return (idx, t['name'].lower())

    return sorted(found.values(), key=sort_key)


_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def extract_script_srcs(html_body: str) -> List[str]:
    """Pull the ``src`` URLs of every ``<script src=…>`` tag from a page body.

    A small stdlib helper so callers (recon) can feed ``fingerprint`` the script
    list without re-implementing the regex.
    """
    return _SCRIPT_SRC_RE.findall(html_body or '')


def render_html(technologies: Optional[List[Dict]]) -> str:
    """Render fingerprinted technologies as a self-contained inline-CSS fragment.

    Groups by category (CATEGORY_ORDER) and shows ``name``/``version`` chips with
    no JavaScript and no external resource (offline invariant I2). Returns a
    short placeholder when nothing was detected.
    """
    e = html.escape
    techs = technologies or []
    if not techs:
        return ('<p style="font-size:13px;color:#999;">'
                'Технологии не определены.</p>')

    by_cat: Dict[str, List[Dict]] = {}
    for t in techs:
        by_cat.setdefault(t.get('category', 'Other'), []).append(t)

    ordered = [c for c in CATEGORY_ORDER if c in by_cat]
    ordered += [c for c in by_cat if c not in CATEGORY_ORDER]

    blocks = []
    for cat in ordered:
        chips = []
        for t in by_cat[cat]:
            ver = t.get('version')
            label = f"{t.get('name', '')} {ver}" if ver else t.get('name', '')
            chips.append(
                f'<span style="display:inline-block;background:#eef2f7;'
                f'border:1px solid #d0d7de;border-radius:12px;padding:2px 10px;'
                f'margin:2px;font-size:12px;color:#243b53;">{e(str(label))}</span>'
            )
        blocks.append(
            f'<div style="margin:6px 0;"><span style="color:#666;font-size:12px;'
            f'display:inline-block;min-width:84px;">{e(cat)}</span>'
            f'{"".join(chips)}</div>'
        )
    return ''.join(blocks)
