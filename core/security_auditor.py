"""core/security_auditor.py

Orchestrates the native-Python Security Audit: fetch a target page and the
JavaScript it loads, then run the shared SecretScanner + SourceMapParser over
everything to surface (1) leaked credentials, (2) endpoint URLs referenced in
code, and (3) exposed/leaking source maps.

This is the headless backend behind the "Security Audit" GUI tab. It is pure
(no Qt) and does blocking network I/O, so it must be called from a worker
thread — the GUI drives it via ``window._start_task`` / ``_run_async``. It
supports cooperative cancellation through a ``threading.Event``, matching the
capture/clone runners.
"""

import gzip
import re
import zlib
from typing import Callable, Dict, List, Optional

from urllib.parse import urljoin

from core.dynamic_analyzer import extract_js_urls
from core.secret_scanner import SecretScanner
from core.source_map_parser import SourceMapParser
from utils.browser_utils import SessionBuilder

# External scripts and inline <script> bodies in an HTML document.
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(
    r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)


class SecurityAuditor:
    """Fetch a site + its JS and report secrets, endpoints and source maps."""

    def __init__(self, profile: str = 'chrome_windows',
                 max_scripts: int = 25, timeout: int = 12):
        self._session = SessionBuilder(profile)
        self._scanner = SecretScanner()
        self._smparser = SourceMapParser(self._scanner)
        self.max_scripts = max_scripts
        self.timeout = timeout
        self.progress_callback: Optional[Callable] = None
        self._cancel = None

    # --------------------------------------------------------------- wiring

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def set_cancel_event(self, event):
        """Provide a threading.Event; audit() bails out cooperatively when set."""
        self._cancel = event

    def _cancelled(self) -> bool:
        return self._cancel is not None and self._cancel.is_set()

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    # ------------------------------------------------------------- fetching

    def _fetch(self, url: str) -> Optional[str]:
        """GET ``url`` and return decoded text, or None on any failure.

        Handles gzip/deflate (urllib does not auto-decompress) so scanning sees
        real source, not compressed bytes.
        """
        try:
            req = self._session.make_request(url)
            opener = self._session.build_opener()
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                enc = (resp.headers.get('Content-Encoding') or '').lower().strip()
            return self._decode(raw, enc)
        except Exception as e:  # noqa: BLE001 — one bad asset must not abort the audit
            self._log(f'  ! fetch failed: {url} ({e})')
            return None

    @staticmethod
    def _decode(raw: bytes, encoding: str) -> str:
        try:
            if encoding == 'gzip' or raw[:2] == b'\x1f\x8b':
                raw = gzip.decompress(raw)
            elif encoding == 'deflate':
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:
            pass
        return raw.decode('utf-8', errors='ignore')

    # ---------------------------------------------------------------- audit

    def audit(self, url: str) -> Dict:
        """Run the full audit and return a structured result.

        Returns ``{status, url, secrets, endpoints, source_maps,
        scanned_scripts, summary, error?}``. Network/parse failures degrade
        gracefully — a single broken asset is skipped, never fatal.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {
            'status': 'Error', 'url': url, 'secrets': [], 'endpoints': [],
            'source_maps': [], 'scanned_scripts': 0, 'summary': {},
        }

        self._log(f'[SecurityAudit] Fetching page: {url}')
        html = self._fetch(url)
        if html is None:
            result['error'] = 'could not fetch target URL'
            return result

        secrets: List[Dict] = list(self._scanner.scan_text(html, url))
        endpoints: Dict[str, Dict] = {}
        source_maps: List[Dict] = []

        # Inline <script> bodies travel with the page.
        for inline in _INLINE_SCRIPT_RE.findall(html):
            secrets.extend(self._scanner.scan_text(inline, url))
            self._collect_urls(extract_js_urls(inline, url), url, endpoints)

        # External scripts, bounded so a page with hundreds of chunks is sane.
        srcs = self._unique_script_srcs(html, url)
        self._log(f'[SecurityAudit] {len(srcs)} external scripts '
                  f'(scanning up to {self.max_scripts})')
        scanned = 0
        for js_url in srcs[:self.max_scripts]:
            if self._cancelled():
                self._log('[SecurityAudit] cancelled')
                break
            js = self._fetch(js_url)
            if js is None:
                continue
            scanned += 1
            secrets.extend(self._scanner.scan_text(js, js_url))
            self._collect_urls(extract_js_urls(js, js_url), js_url, endpoints)
            self._audit_source_maps(js, js_url, secrets, source_maps)

        result['scanned_scripts'] = scanned
        result['secrets'] = self._dedup_secrets(secrets)
        result['endpoints'] = list(endpoints.values())
        result['source_maps'] = source_maps
        result['summary'] = {
            'secrets': len(result['secrets']),
            'endpoints': len(result['endpoints']),
            'source_maps': len(source_maps),
            'maps_with_content': sum(1 for m in source_maps if m.get('has_content')),
            'scanned_scripts': scanned,
        }
        result['status'] = 'Success'
        self._log(
            f'[SecurityAudit] done — {result["summary"]["secrets"]} secrets, '
            f'{result["summary"]["endpoints"]} endpoints, '
            f'{len(source_maps)} source maps'
        )
        return result

    # --------------------------------------------------------------- helpers

    def _unique_script_srcs(self, html: str, base_url: str) -> List[str]:
        seen: set = set()
        out: List[str] = []
        for src in _SCRIPT_SRC_RE.findall(html):
            full = urljoin(base_url, src.strip())
            if full not in seen:
                seen.add(full)
                out.append(full)
        return out

    @staticmethod
    def _collect_urls(urls: List[str], source: str, into: Dict[str, Dict]):
        for u in urls:
            if u not in into:
                into[u] = {'url': u, 'found_in': source}

    def _audit_source_maps(self, js: str, js_url: str,
                           secrets: List[Dict], source_maps: List[Dict]):
        for map_url in self._smparser.find_map_urls(js, js_url):
            if map_url.startswith('data:'):
                continue  # inline data-URI maps: skip the network round-trip
            content = self._fetch(map_url)
            if content is None:
                continue
            parsed = self._smparser.parse(content)
            if not parsed.get('ok'):
                continue
            leaked = self._smparser.scan_for_secrets(content)
            secrets.extend(leaked)
            source_maps.append({
                'url': map_url,
                'js': js_url,
                'sources': len(parsed.get('sources', [])),
                'has_content': parsed.get('has_content', False),
                'secrets': len(leaked),
            })

    @staticmethod
    def _dedup_secrets(secrets: List[Dict]) -> List[Dict]:
        """Collapse identical (type, value, source) findings across assets."""
        seen: set = set()
        out: List[Dict] = []
        for s in secrets:
            key = (s.get('type'), s.get('match'), s.get('source'))
            if key not in seen:
                seen.add(key)
                out.append(s)
        return out
