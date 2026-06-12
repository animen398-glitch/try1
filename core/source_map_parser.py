"""core/source_map_parser.py

Native-Python reimplementation of the useful half of JSMap-Inspector: given a
JavaScript source map (``.js.map``), recover the *original* source tree that
minification was supposed to hide. Modern bundlers often ship (or leak) these
maps, and their ``sourcesContent`` can expose pre-minification code — comments,
internal paths, even credentials.

This module is pure parsing + optional secret scanning. The interactive HTML
viewer (vendor/JSMap-Inspector) can still be shipped as a bundled resource for
manual exploration; this gives the app a headless, scriptable equivalent that
plugs into the Security Audit flow.

Everything here is dependency-free and worker-thread safe. Network fetching is
opt-in (``fetch_and_parse``) and isolated behind the project's SessionBuilder,
so the parsing functions stay unit-testable offline.
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from core.secret_scanner import SecretScanner

# `//# sourceMappingURL=app.js.map` (modern) or the legacy `//@` form, possibly
# trailing the file. Data-URI maps (`data:application/json;base64,…`) are matched
# too so callers can decide whether to decode them.
_SOURCEMAP_URL_RE = re.compile(
    r'(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)')


class SourceMapParser:
    """Parse ``.js.map`` JSON and surface original sources / leaked secrets."""

    def __init__(self, scanner: Optional[SecretScanner] = None):
        self._scanner = scanner or SecretScanner()

    # ------------------------------------------------------------- discovery

    @staticmethod
    def find_map_urls(js_text: str, base_url: str = '') -> List[str]:
        """Extract ``sourceMappingURL`` references from a JS file body.

        Relative references are resolved against ``base_url`` when given.
        Data-URI maps are returned verbatim (the scheme makes them recognisable).
        """
        urls: List[str] = []
        for raw in _SOURCEMAP_URL_RE.findall(js_text or ''):
            ref = raw.strip()
            if not ref:
                continue
            if ref.startswith('data:') or not base_url:
                urls.append(ref)
            else:
                urls.append(urljoin(base_url, ref))
        return urls

    # --------------------------------------------------------------- parsing

    @staticmethod
    def parse(content: str) -> Dict:
        """Parse source-map JSON into a structured summary.

        Returns ``{ok, version, file, sources, names, sources_content_count,
        has_content, error}``. Malformed input yields ``ok=False`` with a
        message rather than raising, so a single bad map never aborts a scan.
        """
        try:
            data = json.loads(content)
        except (ValueError, TypeError) as e:
            return {'ok': False, 'error': f'invalid JSON: {e}', 'sources': []}
        if not isinstance(data, dict):
            return {'ok': False, 'error': 'source map is not a JSON object',
                    'sources': []}

        sources = [s for s in (data.get('sources') or []) if isinstance(s, str)]
        contents = data.get('sourcesContent') or []
        contents = [c for c in contents if isinstance(c, str)]
        return {
            'ok': True,
            'version': data.get('version'),
            'file': data.get('file'),
            'sources': sources,
            'names': [n for n in (data.get('names') or []) if isinstance(n, str)],
            'sources_content_count': len(contents),
            'has_content': bool(contents),
            'error': None,
        }

    @staticmethod
    def extract_sources(content: str) -> List[str]:
        """Just the list of original source paths recorded in the map."""
        return SourceMapParser.parse(content).get('sources', [])

    @staticmethod
    def extract_sources_content(content: str) -> List[Tuple[str, str]]:
        """Pair each original source path with its recovered source text.

        Maps may omit ``sourcesContent`` (then this is empty) or provide fewer
        entries than ``sources``; pairing stops at the shorter of the two.
        """
        try:
            data = json.loads(content)
        except (ValueError, TypeError):
            return []
        if not isinstance(data, dict):
            return []
        sources = data.get('sources') or []
        contents = data.get('sourcesContent') or []
        pairs: List[Tuple[str, str]] = []
        for path, text in zip(sources, contents):
            if isinstance(text, str):
                pairs.append((str(path), text))
        return pairs

    # ---------------------------------------------------------- secret scan

    def scan_for_secrets(self, content: str) -> List[Dict]:
        """Scan every recovered original source for credentials.

        Each finding carries the original source path as its ``source`` so the
        UI can point at the exact (pre-minification) file that leaked.
        """
        items = [(text, path) for path, text in self.extract_sources_content(content)]
        return self._scanner.scan_many(items)

    # --------------------------------------------------------------- network

    def fetch_and_parse(self, url: str, profile: str = 'chrome_windows',
                        timeout: int = 10) -> Dict:
        """Fetch a ``.js.map`` over HTTP and parse it (opt-in, blocking I/O).

        Network is isolated behind SessionBuilder. Call from a worker thread —
        never the GUI thread. Returns :meth:`parse`'s dict plus a ``url`` key,
        or ``ok=False`` on any network error.
        """
        from utils.browser_utils import SessionBuilder
        from utils.http_retry import urlopen_text
        try:
            req = SessionBuilder(profile).make_request(url)
            # gzip-aware (SessionBuilder advertises gzip) + retry on transient.
            content = urlopen_text(req, timeout)
        except Exception as e:  # noqa: BLE001 — network failure must not crash a scan
            return {'ok': False, 'error': f'fetch failed: {e}', 'url': url,
                    'sources': []}
        result = self.parse(content)
        result['url'] = url
        return result
