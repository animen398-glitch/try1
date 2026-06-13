"""Tests for OpenAPI Discovery (core/openapi_discovery.py, roadmap #11).

Pure parsing is tested directly; the network probe is exercised with an
injected fetch, so nothing hits the network.
"""

from core import attack_surface, openapi_discovery, scan_diff

_OPENAPI3 = {
    'openapi': '3.0.1',
    'info': {'title': 'Demo API'},
    'servers': [{'url': 'https://api.demo.com/v1'}],
    'paths': {
        '/users': {
            'get': {'summary': 'List users', 'tags': ['users'],
                    'parameters': [{'name': 'page'}]},
            'post': {'operationId': 'createUser', 'tags': ['users']},
        },
        '/health': {'get': {'summary': 'Health', 'deprecated': True}},
        '/internal': {'x-internal': True},          # no HTTP-verb -> ignored
    },
}

_SWAGGER2 = {
    'swagger': '2.0',
    'info': {'title': 'Legacy'},
    'host': 'old.demo.com',
    'basePath': '/api',
    'schemes': ['https'],
    'paths': {'/ping': {'get': {'summary': 'ping'}}},
}


# ── parse_spec (pure) ─────────────────────────────────────────────────────────

def test_parse_openapi3():
    out = openapi_discovery.parse_spec(_OPENAPI3)
    assert out['version'] == '3.0.1' and out['title'] == 'Demo API'
    assert out['servers'] == ['https://api.demo.com/v1']
    assert out['counts'] == {'paths': 3, 'endpoints': 3}
    methods = {(e['method'], e['path']) for e in out['endpoints']}
    assert ('GET', '/users') in methods and ('POST', '/users') in methods
    health = next(e for e in out['endpoints'] if e['path'] == '/health')
    assert health['deprecated'] is True
    users_get = next(e for e in out['endpoints']
                     if e['path'] == '/users' and e['method'] == 'GET')
    assert users_get['params'] == 1 and users_get['tags'] == ['users']


def test_parse_swagger2_builds_server_from_host():
    out = openapi_discovery.parse_spec(_SWAGGER2)
    assert out['version'] == '2.0'
    assert out['servers'] == ['https://old.demo.com/api']
    assert out['counts']['endpoints'] == 1


def test_parse_rejects_non_spec():
    assert openapi_discovery.parse_spec({'hello': 'world'}) is None
    assert openapi_discovery.parse_spec({'openapi': '3.0'}) is None   # no paths
    assert openapi_discovery.parse_spec('nope') is None


# ── discover (injected fetch, no network) ─────────────────────────────────────

def test_discover_finds_first_spec():
    def fake_fetch(url):
        # Only the swagger.json path returns a spec.
        return _OPENAPI3 if url.endswith('/swagger.json') else None

    out = openapi_discovery.discover('https://demo.com', fetch=fake_fetch)
    assert out['status'] == 'Success'
    assert out['spec_url'] == 'https://demo.com/swagger.json'
    assert out['counts']['endpoints'] == 3


def test_discover_probes_root_not_path():
    seen = []

    def fake_fetch(url):
        seen.append(url)
        return None

    openapi_discovery.discover('https://demo.com/some/deep/page',
                               fetch=fake_fetch)
    assert all(u.startswith('https://demo.com/') for u in seen)
    assert 'https://demo.com/openapi.json' in seen


def test_discover_not_found():
    out = openapi_discovery.discover('https://demo.com', fetch=lambda u: None)
    assert out['status'] == 'Not found'
    assert out['endpoints'] == [] and out['spec_url'] is None


def test_discover_skips_non_spec_json():
    # A path that returns JSON but isn't a spec must be skipped, not matched.
    def fake_fetch(url):
        return {'error': 'not found'}

    assert openapi_discovery.discover('https://demo.com',
                                      fetch=fake_fetch)['status'] == 'Not found'


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline_and_lists_endpoints():
    data = openapi_discovery.discover(
        'https://demo.com',
        fetch=lambda u: _OPENAPI3 if u.endswith('/openapi.json') else None)
    page = openapi_discovery.render_html(data)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert '/users' in page and 'Demo API' in page


def test_render_html_not_found():
    page = openapi_discovery.render_html({'status': 'Not found'})
    assert 'не найдена' in page


# ── integration: scan_diff + attack_surface ───────────────────────────────────

def _report_with_openapi(endpoints):
    return {'phases': {'openapi': {'status': 'Success', 'data': {
        'endpoints': [{'method': m, 'path': p} for m, p in endpoints]}}}}


def test_scan_diff_reports_added_removed_apis():
    a = _report_with_openapi([('GET', '/a'), ('GET', '/b')])
    b = _report_with_openapi([('GET', '/b'), ('POST', '/c')])
    d = scan_diff.diff(a, b)
    apis = d['sections']['apis']
    assert apis['added'] == ['POST /c']
    assert apis['removed'] == ['GET /a']


def test_attack_surface_includes_apis_category():
    report = _report_with_openapi([('GET', '/users'), ('POST', '/users')])
    surface = attack_surface.build_surface(report)
    apis = next((c for c in surface['categories'] if c['name'] == 'APIs'), None)
    assert apis is not None and apis['count'] == 2
