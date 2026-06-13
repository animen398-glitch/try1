"""core/graphql_discovery.py
GraphQL endpoint discovery + introspection check (Security Audit).

Probes a small set of conventional GraphQL paths under the target origin, asks
each a tiny query to confirm it really speaks GraphQL, and then checks whether
schema introspection is left enabled — the single highest-value GraphQL finding
(it hands an attacker the full API surface).

Network I/O is isolated behind ``_post`` (a real ``urllib`` POST via
SessionBuilder), which tests stub — the discovery/classification logic itself is
pure and offline-testable (architectural invariant I5). Like the other network
engines this blocks, so the GUI drives it from a worker thread.
"""

import json
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from utils.browser_utils import SessionBuilder

# Conventional GraphQL mount points, in probe order.
CANDIDATE_PATHS = [
    '/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql',
    '/graphql/console', '/query', '/api/graphql/v1',
]

# Minimal query to confirm a GraphQL handler; introspection query to detect that
# schema introspection is enabled.
_PROBE_QUERY = '{__typename}'
_INTROSPECTION_QUERY = '{__schema{queryType{name} types{name}}}'


class GraphQLDiscovery:
    """Discover GraphQL endpoints under an origin and flag open introspection."""

    def __init__(self, profile: str = 'chrome_windows', timeout: int = 10):
        self._session = SessionBuilder(profile)
        self.timeout = timeout
        self.progress_callback: Optional[Callable] = None

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    # ------------------------------------------------------------- network
    def _post(self, url: str, query: str):
        """POST a GraphQL ``query`` as JSON. Returns ``(status, text)`` or
        ``(None, '')`` on transport failure. Isolated for stubbing in tests."""
        import urllib.request
        from utils.http_retry import decompress, urlopen_retry
        try:
            body = json.dumps({'query': query}).encode('utf-8')
            headers = dict(self._session.get_headers())
            headers['Content-Type'] = 'application/json'
            req = urllib.request.Request(url, data=body, headers=headers,
                                         method='POST')
            raw, resp_headers = urlopen_retry(req, self.timeout)
            return 200, decompress(raw, resp_headers).decode('utf-8', 'ignore')
        except Exception as e:  # noqa: BLE001 — a bad endpoint must not abort
            code = getattr(e, 'code', None)
            return code, ''

    # ------------------------------------------------------------- logic
    @staticmethod
    def _looks_like_graphql(status: Optional[int], text: str) -> bool:
        """A GraphQL handler answers a ``{__typename}`` probe with JSON carrying
        a ``data`` or ``errors`` key (even an error response is a positive)."""
        if not text:
            return False
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return False
        return isinstance(doc, dict) and ('data' in doc or 'errors' in doc)

    @staticmethod
    def _introspection_open(text: str) -> bool:
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return False
        data = doc.get('data') if isinstance(doc, dict) else None
        return bool(isinstance(data, dict) and data.get('__schema'))

    def _origin(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        p = urlparse(url)
        return f'{p.scheme}://{p.netloc}'

    def discover(self, url: str) -> Dict:
        """Probe candidate paths under ``url``'s origin.

        Returns ``{status, origin, endpoints, findings}`` where each endpoint is
        ``{url, graphql, introspection}`` and findings use the vuln-scanner shape.
        """
        origin = self._origin(url)
        endpoints: List[Dict] = []
        findings: List[Dict] = []

        for path in CANDIDATE_PATHS:
            target = origin + path
            status, text = self._post(target, _PROBE_QUERY)
            if not self._looks_like_graphql(status, text):
                continue
            self._log(f'[GraphQL] endpoint: {target}')
            introspection = False
            istatus, itext = self._post(target, _INTROSPECTION_QUERY)
            if self._introspection_open(itext):
                introspection = True
            endpoints.append({'url': target, 'graphql': True,
                              'introspection': introspection})
            if introspection:
                findings.append({
                    'severity': 'Medium',
                    'title': 'GraphQL introspection enabled',
                    'detail': f'{target} — full schema exposed via introspection; '
                              f'disable in production.',
                    'source': 'graphql-discovery',
                })
            else:
                findings.append({
                    'severity': 'Info',
                    'title': 'GraphQL endpoint exposed',
                    'detail': f'{target} — reachable GraphQL API (introspection off).',
                    'source': 'graphql-discovery',
                })

        return {'status': 'Success', 'origin': origin,
                'endpoints': endpoints, 'findings': findings}
