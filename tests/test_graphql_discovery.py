"""GraphQL discovery — probe logic + introspection check (offline via _post stub)."""

import json
from urllib.parse import urlparse

from core.graphql_discovery import GraphQLDiscovery


def _disco(responses, raw=None):
    """Build a discovery whose network is driven by maps keyed by (path, kind).

    ``responses`` drives the string-query seam ``_post`` — kind is 'probe',
    'introspect' or 'suggest'. ``raw`` drives the array seam ``_post_raw`` — kind
    'batch'. Missing keys yield 404 (so by default batching/suggestions are off).
    """
    d = GraphQLDiscovery()
    raw = raw or {}

    def fake_post(url, query):
        if '__schema' in query:
            kind = 'introspect'
        elif 'aaaaaaaaaazzzzzzzzzz' in query:
            kind = 'suggest'
        else:
            kind = 'probe'
        path = urlparse(url).path
        if (path, kind) in responses:
            return 200, responses[(path, kind)]
        return 404, ''

    def fake_post_raw(url, payload):
        path = urlparse(url).path
        if (path, 'batch') in raw:
            return 200, raw[(path, 'batch')]
        return 404, ''

    d._post = fake_post           # type: ignore[assignment]
    d._post_raw = fake_post_raw   # type: ignore[assignment]
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


def test_discover_new_candidate_path_gql():
    d = _disco({('/gql', 'probe'): json.dumps({'data': {}}),
                ('/gql', 'introspect'): json.dumps({'errors': []})})
    out = d.discover('https://ex.com')
    assert out['endpoints'][0]['url'] == 'https://ex.com/gql'


# ── extra hardening checks (D3): field suggestions + query batching ───────────

def test_suggestions_and_batching_classifiers():
    g = GraphQLDiscovery
    assert g._suggestions_enabled('{"errors":[{"message":"Did you mean \\"user\\"?"}]}')
    assert not g._suggestions_enabled('{"errors":[{"message":"unknown field"}]}')
    assert not g._suggestions_enabled('')
    assert g._batching_enabled(json.dumps([{'data': {}}, {'data': {}}]))
    assert not g._batching_enabled(json.dumps({'data': {}}))   # single object
    assert not g._batching_enabled('[1, 2]')                   # not dicts
    assert not g._batching_enabled('garbage')


def test_discover_detects_field_suggestions():
    d = _disco({
        ('/graphql', 'probe'): json.dumps({'data': {'__typename': 'Query'}}),
        ('/graphql', 'introspect'): json.dumps({'errors': [{'message': 'off'}]}),
        ('/graphql', 'suggest'): json.dumps(
            {'errors': [{'message': 'Cannot query field "aaa". Did you mean "about"?'}]}),
    })
    out = d.discover('https://ex.com')
    ep = out['endpoints'][0]
    assert ep['suggestions'] is True and ep['introspection'] is False
    titles = [f['title'] for f in out['findings']]
    assert 'GraphQL field suggestions enabled' in titles


def test_discover_detects_query_batching():
    d = _disco(
        {('/graphql', 'probe'): json.dumps({'data': {'__typename': 'Query'}}),
         ('/graphql', 'introspect'): json.dumps({'errors': [{'message': 'off'}]})},
        raw={('/graphql', 'batch'): json.dumps(
            [{'data': {'__typename': 'Query'}}, {'data': {'__typename': 'Query'}}])},
    )
    out = d.discover('https://ex.com')
    ep = out['endpoints'][0]
    assert ep['batching'] is True
    batch_f = next(f for f in out['findings']
                   if f['title'] == 'GraphQL query batching enabled')
    assert batch_f['severity'] == 'Medium'


def test_discover_no_extra_findings_when_hardened():
    # Introspection off, no suggestions, no batching → only the Info exposure.
    d = _disco({
        ('/graphql', 'probe'): json.dumps({'data': {'__typename': 'Query'}}),
        ('/graphql', 'introspect'): json.dumps({'errors': [{'message': 'off'}]}),
    })
    out = d.discover('https://ex.com')
    assert [f['severity'] for f in out['findings']] == ['Info']
    ep = out['endpoints'][0]
    assert ep['suggestions'] is False and ep['batching'] is False
