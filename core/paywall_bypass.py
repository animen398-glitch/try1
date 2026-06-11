import gzip
import json
import re
import urllib.request
import zlib
from typing import Dict, List, Optional
from urllib.parse import quote, urljoin, urlparse, urlunparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_retry


_GOOGLEBOT_UA = (
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
)
_WAYBACK_API = 'https://archive.org/wayback/available?url={encoded}'
_GOOGLE_CACHE = 'https://webcache.googleusercontent.com/search?q=cache:{encoded}'
# Many metered paywalls exempt visitors arriving from search/social.
_SEARCH_REFERER = 'https://www.google.com/'

# Patterns that indicate active paywall enforcement in HTML or scripts
_PAYWALL_RE = re.compile(
    r'paywall|membership|premium-reg|modal-overlay|'
    r'subscribe-wall|metered-content|hard-?wall|'
    r'piano\.io|tinypass|leaky-?paywall|'
    r'paid.?content|content-?gate',
    re.IGNORECASE,
)

# Script src patterns that deliver paywall enforcement
_PAYWALL_SRC_RE = re.compile(
    r'paywall|subscribe|membership|premium|piano|tinypass',
    re.IGNORECASE,
)


def _decompress(raw: bytes, headers) -> bytes:
    enc = headers.get('Content-Encoding', '').lower().strip()
    if enc == 'gzip' or (not enc and raw[:2] == b'\x1f\x8b'):
        return gzip.decompress(raw)
    if enc == 'deflate':
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw


class PaywallBypass:
    """
    Sequential 3-strategy paywall extractor.

    Strategy 1 — Googlebot spoofing:
        Sends the exact Googlebot/2.1 User-Agent which many publishers
        exempt from paywalls to ensure Google indexes their content.

    Strategy 2 — Client-side JS stripping:
        Downloads the page with a normal UA, then removes <script> blocks
        and external script tags whose src / body contain paywall keywords.

    Strategy 3 — Wayback Machine archival fetch:
        Queries archive.org availability API for the latest unrestricted
        snapshot and downloads it from the Wayback CDX endpoint.
    """

    def __init__(self):
        self._timeout: int = 20

    def configure(self, timeout: int = 20):
        self._timeout = timeout

    # ---------------------------------------------------------------- internal

    def _fetch_raw(self, url: str, ua: Optional[str] = None,
                   referer: Optional[str] = None) -> Optional[bytes]:
        try:
            headers = SessionBuilder('chrome_windows').get_headers()
            if ua:
                headers['User-Agent'] = ua
            if referer:
                headers['Referer'] = referer
            req = urllib.request.Request(url, headers=headers)
            raw, resp_headers = urlopen_retry(req, self._timeout)
            return _decompress(raw, resp_headers)
        except Exception:
            return None

    def _fetch_clean(self, url: str, ua: Optional[str] = None,
                     referer: Optional[str] = None) -> Optional[str]:
        """Fetch a URL and return its HTML only if it is not paywalled."""
        raw = self._fetch_raw(url, ua=ua, referer=referer)
        if not raw:
            return None
        html = self._decode(raw)
        return html if not self._is_paywalled(html) else None

    @staticmethod
    def _decode(raw: bytes) -> str:
        return raw.decode('utf-8', errors='ignore')

    @staticmethod
    def _is_paywalled(html: str) -> bool:
        return bool(_PAYWALL_RE.search(html))

    @staticmethod
    def _strip_paywall_js(html: str) -> str:
        """
        Remove external <script src="…"> whose src URL matches paywall patterns,
        and inline <script>…</script> blocks whose body matches them.
        Returns the stripped HTML string.
        """
        def maybe_remove_external(m):
            tag = m.group(0)
            src_m = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if src_m and _PAYWALL_SRC_RE.search(src_m.group(1)):
                return f'<!-- [PaywallBypass] removed external: {src_m.group(1)[:60]} -->'
            return tag

        def maybe_remove_inline(m):
            body = m.group(1)
            if _PAYWALL_RE.search(body):
                return '<!-- [PaywallBypass] removed inline script block -->'
            return m.group(0)

        # External scripts (self-closing or with explicit close)
        html = re.sub(
            r'<script[^>]+src=["\'][^"\']+["\'][^>]*/?>(?:</script>)?',
            maybe_remove_external,
            html,
            flags=re.IGNORECASE,
        )
        # Inline script blocks
        html = re.sub(
            r'<script[^>]*>(.*?)</script>',
            maybe_remove_inline,
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        return html

    @staticmethod
    def _discover_amp(html: str, base_url: str) -> Optional[str]:
        """Return the absolute AMP URL from <link rel="amphtml">, if present."""
        m = re.search(r'<link\b[^>]*\bamphtml\b[^>]*>', html, re.IGNORECASE)
        if not m:
            return None
        href = re.search(r'href=["\']([^"\']+)["\']', m.group(0), re.IGNORECASE)
        return urljoin(base_url, href.group(1)) if href else None

    @staticmethod
    def _amp_candidates(url: str) -> List[str]:
        """Common AMP URL variants to try when no amphtml link is declared."""
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        candidates = [
            urlunparse(parsed._replace(path=f'{path}/amp')),
            urlunparse(parsed._replace(path=f'{path}.amp')),
            urlunparse(parsed._replace(
                query=(parsed.query + '&' if parsed.query else '') + 'outputType=amp')),
            urlunparse(parsed._replace(
                query=(parsed.query + '&' if parsed.query else '') + 'amp=1')),
        ]
        # De-dupe while preserving order.
        seen: set = set()
        return [c for c in candidates if not (c in seen or seen.add(c))]

    @staticmethod
    def _google_cache_url(url: str) -> str:
        return _GOOGLE_CACHE.format(encoded=quote(url, safe=''))

    @staticmethod
    def _reader_view(html: str) -> str:
        """Produce a simplified, reader-mode HTML view of an article.

        Lightweight readability: prefer the <article>/<main> region, drop
        chrome (scripts, nav, asides, …) and keep headings and paragraphs.
        """
        region = html
        for tag in ('article', 'main'):
            m = re.search(rf'<{tag}\b[^>]*>(.*?)</{tag}>', html,
                          re.IGNORECASE | re.DOTALL)
            if m:
                region = m.group(1)
                break

        for tag in ('script', 'style', 'nav', 'header', 'footer', 'aside',
                    'form', 'noscript', 'svg', 'figure'):
            region = re.sub(rf'<{tag}\b[^>]*>.*?</{tag}>', ' ', region,
                            flags=re.IGNORECASE | re.DOTALL)

        tm = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        title = re.sub(r'\s+', ' ', tm.group(1)).strip() if tm else ''

        parts: List[str] = []
        for tag, inner in re.findall(r'<(h[1-3]|p)\b[^>]*>(.*?)</\1>', region,
                                     re.IGNORECASE | re.DOTALL):
            text = re.sub(r'<[^>]+>', '', inner)
            text = re.sub(r'\s+', ' ', text).strip()
            if text:
                t = tag.lower()
                parts.append(f'<{t}>{text}</{t}>' if t.startswith('h')
                             else f'<p>{text}</p>')

        body = '\n'.join(parts)
        return (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            f'<title>{title}</title></head><body><article>'
            f'<h1>{title}</h1>{body}</article></body></html>'
        )

    def _wayback_fetch(self, url: str) -> Optional[str]:
        api_url = _WAYBACK_API.format(encoded=quote(url, safe=''))
        raw = self._fetch_raw(api_url)
        if not raw:
            return None
        try:
            data = json.loads(raw.decode('utf-8', errors='ignore'))
            snapshot = (
                data.get('archived_snapshots', {})
                    .get('closest', {})
            )
            snapshot_url = snapshot.get('url')
            if not snapshot_url:
                return None
            snap_raw = self._fetch_raw(snapshot_url)
            if snap_raw:
                return self._decode(snap_raw)
        except Exception:
            pass
        return None

    # ---------------------------------------------------------------- public

    def _win(self, result: Dict, strategy: str, html: str) -> Dict:
        """Finalize a successful extraction: set html, strategy and reader view."""
        result.update({
            'strategy_used': strategy,
            'html': html,
            'reader_view': self._reader_view(html),
            'status': 'Success',
        })
        return result

    def extract(self, url: str) -> Dict:
        """
        Run the strategies in order, returning on the first success:
          1. googlebot_spoof   — Googlebot User-Agent
          2. js_strip          — remove paywall scripts from the response
          3. amp               — AMP version (declared amphtml link or variants)
          4. referer_spoof     — arrive "from Google" (metered-paywall exemption)
          5. google_cache      — Google's cached copy
          6. wayback_machine   — archive.org snapshot

        Returns a dict: {url, strategy_used, html, reader_view, paywalled, status}.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {
            'url': url,
            'strategy_used': None,
            'html': None,
            'reader_view': None,
            'paywalled': False,
            'status': 'Failed',
        }

        base_html: Optional[str] = None

        # ── Strategy 1: Googlebot spoofing ───────────────────────────────
        raw = self._fetch_raw(url, ua=_GOOGLEBOT_UA)
        if raw:
            base_html = self._decode(raw)
            if not self._is_paywalled(base_html):
                return self._win(result, 'googlebot_spoof', base_html)
            result['paywalled'] = True

            # ── Strategy 2: strip paywall JS from the googlebot response ──
            stripped = self._strip_paywall_js(base_html)
            if stripped != base_html:
                return self._win(result, 'js_strip', stripped)

        # ── Strategy 3: AMP version ──────────────────────────────────────
        amp_url = self._discover_amp(base_html, url) if base_html else None
        amp_targets = ([amp_url] if amp_url else []) + self._amp_candidates(url)
        for target in amp_targets:
            amp_html = self._fetch_clean(target)
            if amp_html:
                return self._win(result, 'amp', amp_html)

        # ── Strategy 4: referrer spoofing (arrive from search) ───────────
        ref_html = self._fetch_clean(url, referer=_SEARCH_REFERER)
        if ref_html:
            return self._win(result, 'referer_spoof', ref_html)

        # ── Strategy 5: Google cache ─────────────────────────────────────
        cache_html = self._fetch_clean(self._google_cache_url(url))
        if cache_html:
            return self._win(result, 'google_cache', cache_html)

        # ── Strategy 6: Wayback Machine archival snapshot ────────────────
        archived = self._wayback_fetch(url)
        if archived:
            return self._win(result, 'wayback_machine', archived)

        return result
