import gzip
import json
import re
import urllib.request
import zlib
from typing import Dict, Optional
from urllib.parse import quote, urlparse

from utils.browser_utils import SessionBuilder


_GOOGLEBOT_UA = (
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
)
_WAYBACK_API = 'https://archive.org/wayback/available?url={encoded}'

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

    def _fetch_raw(self, url: str, ua: Optional[str] = None) -> Optional[bytes]:
        try:
            headers = SessionBuilder('chrome_windows').get_headers()
            if ua:
                headers['User-Agent'] = ua
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                raw = r.read()
                return _decompress(raw, r.headers)
        except Exception:
            return None

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

    def extract(self, url: str) -> Dict:
        """
        Run all 3 strategies in order, return on first success.

        Returns:
            {
                url: str,
                strategy_used: str | None,
                html: str | None,       # decoded HTML text, UTF-8
                paywalled: bool,        # True if original response showed a paywall
                status: 'Success' | 'Failed',
            }
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {
            'url': url,
            'strategy_used': None,
            'html': None,
            'paywalled': False,
            'status': 'Failed',
        }

        # ── Strategy 1: Googlebot spoofing ───────────────────────────────
        raw = self._fetch_raw(url, ua=_GOOGLEBOT_UA)
        if raw:
            html = self._decode(raw)
            if not self._is_paywalled(html):
                result.update({
                    'strategy_used': 'googlebot_spoof',
                    'html': html,
                    'status': 'Success',
                })
                return result
            result['paywalled'] = True

            # ── Strategy 2: strip paywall JS from the googlebot response ──
            stripped = self._strip_paywall_js(html)
            if stripped != html:
                result.update({
                    'strategy_used': 'js_strip',
                    'html': stripped,
                    'status': 'Success',
                })
                return result

        # ── Strategy 3: Wayback Machine archival snapshot ────────────────
        archived = self._wayback_fetch(url)
        if archived:
            result.update({
                'strategy_used': 'wayback_machine',
                'html': archived,
                'status': 'Success',
            })
            return result

        return result
