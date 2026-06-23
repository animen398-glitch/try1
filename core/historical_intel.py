"""core/historical_intel.py
Historical URL Intelligence — what a target *used* to expose, from public web
archives (roadmap #12).

Queries the Wayback Machine CDX index (free, no key, stdlib-only) for every URL
ever archived under a domain, then classifies them to surface the interesting
history: old admin panels, auth pages, API endpoints, and exposed config/backup
files that may still linger.

Invariants:
  * I1 — stdlib only (json + urllib via SessionBuilder). Common Crawl / OTX are
    deliberately out of scope here (heavier / key-gated); the source layer is
    structured so another archive could be added later.
  * I5 — the network fetch (``fetch_wayback``) is separated from the pure
    classifier (``classify`` / ``analyze``) and is injectable into ``discover``,
    so tests never hit the network.
"""

import html
import json
from typing import Callable, Dict, List, Optional
from urllib.parse import quote, urlparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

WAYBACK_CDX = 'https://web.archive.org/cdx/search/cdx'
_FETCH_TIMEOUT = 25.0
_DEFAULT_LIMIT = 1000

# Path/extension signatures → category. Order does not matter; a URL can land in
# several categories. Substring match on the lowercased URL.
CATEGORY_RULES = {
    'admin': ('/admin', 'wp-admin', 'administrator', '/manage', '/dashboard',
              'cpanel', '/panel', '/console'),
    'auth': ('/login', 'signin', '/auth', 'oauth', '/logout', '/register',
             '/sso', 'password'),
    'api': ('/api/', '/api.', '/graphql', '/rest/', '/v1/', '/v2/', '/v3/',
            'swagger', 'openapi', '.json'),
    'config': ('.env', '.bak', '.old', '.config', '/config', 'backup', '.sql',
               '.zip', '.tar', '.gz', '.git', '.yml', '.yaml', '.ini'),
    'upload': ('/upload', '/files/', '/media/', '/attachments'),
    'docs': ('/docs', 'redoc', 'api-docs', 'readme'),
}

# The security-relevant subset that makes a historical URL worth a closer look.
INTERESTING_CATEGORIES = ('admin', 'auth', 'config', 'api')


# ── network (injectable; kept out of the pure classifier) ─────────────────────

def fetch_wayback(domain: str, limit: int = _DEFAULT_LIMIT,
                  timeout: float = _FETCH_TIMEOUT,
                  profile: str = 'chrome_windows') -> List[Dict]:
    """Fetch archived URLs for ``domain`` from the Wayback CDX API.

    Returns ``[{url, timestamp, status}]``, or [] on any failure — the caller
    treats an empty result as "no history". Duplicates are removed downstream in
    ``analyze`` (server-side ``collapse`` is omitted: on a wildcard query it is
    expensive enough to 504 the CDX gateway)."""
    q = (f'{WAYBACK_CDX}?url={quote(domain)}/*&output=json'
         f'&fl=original,timestamp,statuscode&limit={int(limit)}')
    try:
        req = SessionBuilder(profile).make_request(q)
        text = urlopen_text(req, timeout, attempts=2)
        rows = json.loads(text)
    except Exception:
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    # First row is the header (original/timestamp/statuscode).
    out: List[Dict] = []
    for row in rows[1:]:
        if isinstance(row, list) and row:
            out.append({'url': row[0],
                        'timestamp': row[1] if len(row) > 1 else '',
                        'status': row[2] if len(row) > 2 else ''})
    return out


# ── pure classification ───────────────────────────────────────────────────────

def classify(url: str) -> List[str]:
    """Categories a URL falls into (substring heuristics on the lowercased URL)."""
    low = str(url).lower()   # tolerate a non-str url (degrade, never raise)
    return [cat for cat, sigs in CATEGORY_RULES.items()
            if any(s in low for s in sigs)]


def analyze(entries: List) -> Dict:
    """Classify archived entries into categories + an "interesting" subset (pure).

    ``entries`` may be URL strings or ``{url,...}`` dicts. Returns
    ``{total, categories: {cat: [urls]}, interesting: [urls]}`` with empty
    categories omitted and every URL list de-duplicated (order preserved)."""
    seen: set = set()
    urls: List[str] = []
    for e in entries:
        u = e.get('url') if isinstance(e, dict) else e
        if not u:
            continue
        # Coerce before the dedup check: a malformed entry (e.g. a list) is
        # unhashable, and `u in seen` would raise — degrade, never raise.
        u = str(u)
        if u not in seen:
            seen.add(u)
            urls.append(u)

    categories: Dict[str, List[str]] = {}
    interesting: List[str] = []
    for u in urls:
        cats = classify(u)
        for c in cats:
            categories.setdefault(c, []).append(u)
        if any(c in INTERESTING_CATEGORIES for c in cats):
            interesting.append(u)

    return {'total': len(urls), 'categories': categories,
            'interesting': interesting}


# ── discovery (fetch + analyze) ───────────────────────────────────────────────

def discover(target: str, limit: int = _DEFAULT_LIMIT,
             timeout: float = _FETCH_TIMEOUT, profile: str = 'chrome_windows',
             fetch: Optional[Callable] = None) -> Dict:
    """Fetch a target's archived URLs and classify them.

    ``fetch(domain)`` overrides the default Wayback getter (tests inject a fake).
    Returns ``{status, source, domain, total, categories, interesting}``."""
    domain = urlparse(target if '://' in target else 'https://' + target).netloc \
        or target
    getter = fetch or (lambda d: fetch_wayback(d, limit, timeout, profile))
    entries = getter(domain)
    if not entries:
        return {'status': 'No history', 'source': 'wayback', 'domain': domain,
                'total': 0, 'categories': {}, 'interesting': []}
    result = analyze(entries)
    result.update({'status': 'Success', 'source': 'wayback', 'domain': domain})
    return result


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

_CAT_LABELS = {'admin': 'Админки', 'auth': 'Авторизация', 'api': 'API',
               'config': 'Конфиги / бэкапы', 'upload': 'Загрузки', 'docs': 'Доки'}


def render_html(data: Dict) -> str:
    """Render the historical-URL summary as an offline HTML fragment."""
    e = html.escape
    if not data or data.get('status') != 'Success':
        return '<p style="font-size:13px;color:#999;">Историч. URL не найдено</p>'

    cats = data.get('categories', {})
    head = (f'<p style="font-size:13px;">Архивных URL: '
            f'<b>{e(str(data.get("total", 0)))}</b> '
            f'(источник: {e(str(data.get("source", "")))}), интересных: '
            f'<b>{e(str(len(data.get("interesting", []))))}</b></p>')

    # Category counts line.
    counts = ' · '.join(
        f'{_CAT_LABELS.get(c, c)}: {len(v)}'
        for c, v in sorted(cats.items(), key=lambda kv: -len(kv[1])))
    counts_line = (f'<p style="font-size:12px;color:#666;">{e(counts)}</p>'
                   if counts else '')

    # Interesting URLs (capped).
    items = ''.join(f'<li style="margin:1px 0;font-family:monospace;font-size:12px;'
                    f'word-break:break-all;">{e(u)}</li>'
                    for u in (data.get('interesting') or [])[:60])
    body = (f'<ul style="margin:6px 0;max-height:260px;overflow:auto;">{items}</ul>'
            if items else '')
    return head + counts_line + body
