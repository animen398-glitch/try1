"""Tests for core.security_auditor — offline via a stubbed _fetch (no network)."""

import json
import threading

from core.security_auditor import SecurityAuditor

_HTML = """
<html><head>
  <script>var inlineKey = "AKIA1234567890ABCD56"; fetch("/api/v1/me");</script>
  <script src="/static/app.js"></script>
  <script src="https://cdn.example.com/vendor.js"></script>
</head><body>ok</body></html>
"""

_APP_JS = (
    'const token="ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
    'api("/api/v2/orders");'
    '//# sourceMappingURL=app.js.map'
)

_APP_MAP = json.dumps({
    "version": 3,
    "sources": ["src/secret.js"],
    "sourcesContent": ["const stripe='sk_live_abcdefghijklmnopqrstuvwx';"],
})

# URL -> body served by the fake fetcher.
_CORPUS = {
    "https://t.example.com": _HTML,
    "https://t.example.com/static/app.js": _APP_JS,
    "https://t.example.com/static/app.js.map": _APP_MAP,
    "https://cdn.example.com/vendor.js": "console.log('clean');",
}


def _auditor(corpus=_CORPUS, graphql=False):
    # GraphQL probing does real POSTs; keep it off for the offline secret/map
    # tests (it has its own stubbed test below).
    a = SecurityAuditor(graphql=graphql)
    a._fetch = lambda url: corpus.get(url)   # type: ignore[assignment]
    return a


def test_graphql_discovery_folds_into_result(monkeypatch):
    a = _auditor(graphql=True)
    # Stub the network: /graphql speaks GraphQL with introspection open.
    def fake_discover(url):
        return {'endpoints': [
            {'url': 'https://t.example.com/graphql', 'graphql': True,
             'introspection': True}]}
    monkeypatch.setattr(
        'core.graphql_discovery.GraphQLDiscovery.discover',
        lambda self, url: fake_discover(url))
    result = a.audit('https://t.example.com')
    assert result['summary']['graphql'] == 1
    assert result['summary']['graphql_introspection'] == 1
    assert result['graphql'][0]['url'].endswith('/graphql')


def test_audit_collects_secrets_endpoints_and_maps():
    result = _auditor().audit("https://t.example.com")
    assert result["status"] == "Success"

    types = {s["type"] for s in result["secrets"]}
    assert "AWS Access Key" in types          # inline <script>
    assert "GitHub Token" in types            # external app.js
    assert "Stripe Secret" in types           # leaked via source map content

    eps = {e["url"] for e in result["endpoints"]}
    assert "https://t.example.com/api/v1/me" in eps     # inline, resolved
    assert "https://t.example.com/api/v2/orders" in eps  # from app.js

    assert result["scanned_scripts"] == 2
    assert len(result["source_maps"]) == 1
    assert result["source_maps"][0]["secrets"] == 1
    assert result["source_maps"][0]["has_content"] is True


def test_summary_counts_match_lists():
    result = _auditor().audit("https://t.example.com")
    s = result["summary"]
    assert s["secrets"] == len(result["secrets"])
    assert s["endpoints"] == len(result["endpoints"])
    assert s["source_maps"] == 1 and s["maps_with_content"] == 1


def test_unreachable_target_degrades_gracefully():
    result = _auditor(corpus={}).audit("https://nope.example.com")
    assert result["status"] == "Error"
    assert "could not fetch" in result["error"]


def test_cancel_event_stops_before_external_scripts():
    ev = threading.Event()
    ev.set()
    a = _auditor()
    a.set_cancel_event(ev)
    result = a.audit("https://t.example.com")
    # Cancelled before fetching any external script.
    assert result["status"] == "Success"
    assert result["scanned_scripts"] == 0


def test_secrets_are_deduped_across_assets():
    same = 'k="ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
    corpus = {
        "https://d.example.com": '<script src="/a.js"></script><script src="/b.js"></script>',
        "https://d.example.com/a.js": same,
        "https://d.example.com/b.js": same,
    }
    result = _auditor(corpus).audit("https://d.example.com")
    gh = [s for s in result["secrets"] if s["type"] == "GitHub Token"]
    # Same value, different source files -> two findings (source differs), but
    # each (type, value, source) appears once.
    assert len(gh) == 2
    assert {s["source"] for s in gh} == {
        "https://d.example.com/a.js", "https://d.example.com/b.js"}
