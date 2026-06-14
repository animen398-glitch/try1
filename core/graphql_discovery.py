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
    '/v2/graphql', '/graphiql', '/playground', '/gql',
]

# Minimal query to confirm a GraphQL handler; introspection query to detect that
# schema introspection is enabled.
_PROBE_QUERY = '{__typename}'
_INTROSPECTION_QUERY = '{__schema{queryType{name} types{name}}}'
# A query for a field that almost certainly does not exist: a server with field
# suggestions enabled answers with a "Did you mean …" hint, which leaks schema
# detail even when introspection is disabled.
_SUGGESTION_QUERY = '{aaaaaaaaaazzzzzzzzzz}'
# A batched (array) request: a server that executes it returns an array of
# results, i.e. query batching is enabled (an amplification / DoS vector).
_BATCH_QUERY = [{'query': '{__typename}'}, {'query': '{__typename}'}]


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
    def _post_raw(self, url: str, payload):
        """POST an arbitrary JSON ``payload`` (object for a single query, array
        for a batch). Returns ``(status, text)`` or ``(None, '')`` on transport
        failure. The single network seam — stub this (or ``_post``) in tests."""
        import urllib.request
        from utils.http_retry import decompress, urlopen_retry
        try:
            body = json.dumps(payload).encode('utf-8')
            headers = dict(self._session.get_headers())
            headers['Content-Type'] = 'application/json'
            req = urllib.request.Request(url, data=body, headers=headers,
                                         method='POST')
            raw, resp_headers = urlopen_retry(req, self.timeout)
            return 200, decompress(raw, resp_headers).decode('utf-8', 'ignore')
        except Exception as e:  # noqa: BLE001 — a bad endpoint must not abort
            code = getattr(e, 'code', None)
            return code, ''

    def _post(self, url: str, query: str):
        """POST a single GraphQL ``query`` string as JSON (thin over _post_raw)."""
        return self._post_raw(url, {'query': query})

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

    @staticmethod
    def _suggestions_enabled(text: str) -> bool:
        """A 'Did you mean …' hint in the error reply means field suggestions are
        on — it leaks valid schema names even when introspection is disabled."""
        return bool(text) and 'did you mean' in text.lower()

    @staticmethod
    def _batching_enabled(text: str) -> bool:
        """A JSON *array* reply to a batched array request means the server
        executed the batch — an amplification / brute-force / DoS vector."""
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return False
        return (isinstance(doc, list) and len(doc) >= 2
                and all(isinstance(x, dict) for x in doc))

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

            # Extra hardening checks (valuable even when introspection is off).
            _, stext = self._post(target, _SUGGESTION_QUERY)
            suggestions = self._suggestions_enabled(stext)
            _, btext = self._post_raw(target, _BATCH_QUERY)
            batching = self._batching_enabled(btext)

            endpoints.append({'url': target, 'graphql': True,
                              'introspection': introspection,
                              'suggestions': suggestions, 'batching': batching})
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
            if suggestions:
                findings.append({
                    'severity': 'Info',
                    'title': 'GraphQL field suggestions enabled',
                    'detail': f'{target} — server returns "Did you mean" hints, '
                              f'leaking valid schema names even with introspection '
                              f'disabled.',
                    'source': 'graphql-discovery',
                })
            if batching:
                findings.append({
                    'severity': 'Medium',
                    'title': 'GraphQL query batching enabled',
                    'detail': f'{target} — accepts batched array queries, enabling '
                              f'request amplification / brute-force / DoS.',
                    'source': 'graphql-discovery',
                })

        return {'status': 'Success', 'origin': origin,
                'endpoints': endpoints, 'findings': findings}
