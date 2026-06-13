"""GraphQL discovery — probe logic + introspection check (offline via _post stub)."""

import json
from urllib.parse import urlparse

from core.graphql_discovery import GraphQLDiscovery


def _disco(responses):
    """Build a discovery whose _post is driven by a {(path, kind): text} map,
    where path is the exact URL path and kind is 'probe' or 'introspect'."""
    d = GraphQLDiscovery()

    def fake_post(url, query):
        kind = 'introspect' if '__schema' in query else 'probe'
        path = urlparse(url).path
        if (path, kind) in responses:
            return 200, responses[(path, kind)]
        return 404, ''

    d._post = fake_post   # type: ignore[assignment]
    return d


# ── classification helpers ──────────────────────────────────────────────────

def test_looks_like_graphql_on_data_or_errors():
    g = GraphQLDiscovery
    assert g._looks_like_graphql(200, json.dumps({'data': {'__typename': 'Query'}}))
    assert g._looks_like_graphql(400, json.dumps({'errors': [{'message': 'x'}]}))
    assert not g._looks_like_graphql(200, '<html>not json</html>')
    assert not g._looks_like_graphql(200, '')


def test_introspection_open_detects_schema():
    g = GraphQLDiscovery
    assert g._introspection_open(json.dumps({'data': {'__schema': {'types': []}}}))
    assert not g._introspection_open(json.dumps({'errors': [{'message': 'off'}]}))
    assert not g._introspection_open('garbage')


# ── discover ────────────────────────────────────────────────────────────────

def test_discover_finds_endpoint_with_introspection_open():
    d = _disco({
        ('/graphql', 'probe'): json.dumps({'data': {'__typename': 'Query'}}),
        ('/graphql', 'introspect'): json.dumps({'data': {'__schema': {'types': []}}}),
    })
    out = d.discover('https://ex.com/some/page')
    assert out['origin'] == 'https://ex.com'
    assert len(out['endpoints']) == 1
    ep = out['endpoints'][0]
    assert ep['url'] == 'https://ex.com/graphql' and ep['introspection'] is True
    f = out['findings'][0]
    assert f['severity'] == 'Medium' and 'introspection' in f['title'].lower()
    assert f['source'] == 'graphql-discovery'


def test_discover_endpoint_with_introspection_disabled_is_info():
    d = _disco({
        ('/api/graphql', 'probe'): json.dumps({'errors': [{'message': 'need query'}]}),
        ('/api/graphql', 'introspect'): json.dumps({'errors': [{'message': 'disabled'}]}),
    })
    out = d.discover('https://ex.com')
    ep = out['endpoints'][0]
    assert ep['url'] == 'https://ex.com/api/graphql'
    assert ep['introspection'] is False
    assert out['findings'][0]['severity'] == 'Info'


def test_discover_no_graphql_anywhere():
    d = _disco({})    # every path 404s
    out = d.discover('https://ex.com')
    assert out['endpoints'] == []
    assert out['findings'] == []
    assert out['status'] == 'Success'


def test_discover_adds_scheme_when_missing():
    d = _disco({
        ('/graphql', 'probe'): json.dumps({'data': {}}),
        ('/graphql', 'introspect'): json.dumps({'errors': []}),
    })
    out = d.discover('ex.com')
    assert out['origin'] == 'https://ex.com'
