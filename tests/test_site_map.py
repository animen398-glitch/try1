"""Visual Site Map — tree building, status classification and HTML render.

All offline: the pure ``core.site_map`` helpers plus a stubbed-fetch check that
``SiteContentCapture`` threads HTTP statuses into ``site_map.json``.
"""

import json

from core import site_map
from core.content_capture import SiteContentCapture


# ── classify_status ─────────────────────────────────────────────────────────

def test_classify_status_groups():
    assert site_map.classify_status(200)['group'] == '2xx'
    assert site_map.classify_status(301)['group'] == '3xx'
    assert site_map.classify_status(404)['group'] == '4xx'
    assert site_map.classify_status(503)['group'] == '5xx'
    # No status (transport error) and out-of-range codes fall back to 'err'.
    assert site_map.classify_status(None)['group'] == 'err'
    assert site_map.classify_status(0)['group'] == 'err'
    # Every group maps to a colour.
    assert site_map.classify_status(200)['color'].startswith('#')


# ── classify_type ───────────────────────────────────────────────────────────

def test_classify_type_labels():
    assert site_map.classify_type('text/html') == 'html'
    assert site_map.classify_type('application/json') == 'json'
    assert site_map.classify_type('application/javascript') == 'js'
    assert site_map.classify_type('image/png') == 'image'
    assert site_map.classify_type('') == ''
    assert site_map.classify_type(None) == ''


# ── depth + content_type in tree / summary ──────────────────────────────────

def test_build_tree_records_depth_and_type():
    pages = [
        {'url': 'https://ex.com/blog/post', 'status': 200,
         'content_type': 'text/html', 'depth': 2},
    ]
    tree = site_map.build_tree(pages)
    blog = tree['children']['blog']
    post = blog['children']['post']
    assert blog['depth'] == 1
    assert post['depth'] == 2
    assert post['content_type'] == 'text/html'


def test_summarize_reports_max_depth():
    pages = [
        {'url': 'https://ex.com/', 'status': 200},
        {'url': 'https://ex.com/a/b/c', 'status': 200},
    ]
    summary = site_map.summarize(pages)
    assert summary['max_depth'] == 3


def test_render_html_shows_type_chip_and_depth():
    pages = [{'url': 'https://ex.com/api', 'status': 200,
              'content_type': 'application/json', 'depth': 1}]
    out = site_map.render_html(pages)
    assert 'json' in out               # response-type chip
    assert 'глубина' in out            # max-depth in legend


# ── build_tree ──────────────────────────────────────────────────────────────

def test_build_tree_nests_by_path_segments():
    pages = [
        {'url': 'https://ex.com/', 'status': 200},
        {'url': 'https://ex.com/blog', 'status': 200},
        {'url': 'https://ex.com/blog/post', 'status': 200},
        {'url': 'https://ex.com/admin', 'status': 403},
        {'url': 'https://ex.com/missing', 'status': 404},
    ]
    tree = site_map.build_tree(pages)

    # Root is the '/' page itself.
    assert tree['status'] == 200
    assert set(tree['children']) == {'blog', 'admin', 'missing'}

    blog = tree['children']['blog']
    assert blog['status'] == 200
    assert blog['path'] == '/blog'
    assert set(blog['children']) == {'post'}
    assert blog['children']['post']['status'] == 200

    assert tree['children']['admin']['status'] == 403
    assert tree['children']['missing']['status'] == 404


def test_build_tree_creates_intermediate_path_nodes_without_status():
    # /a/b is crawled but /a itself never was → 'a' is a structural node.
    pages = [{'url': 'https://ex.com/a/b', 'status': 200}]
    tree = site_map.build_tree(pages)
    node_a = tree['children']['a']
    assert node_a['status'] is None        # intermediate, no page of its own
    assert node_a['url'] is None
    assert node_a['children']['b']['status'] == 200


def test_build_tree_is_order_independent():
    a = [{'url': 'https://e/x/y', 'status': 200},
         {'url': 'https://e/x', 'status': 200}]
    b = list(reversed(a))
    assert site_map.build_tree(a) == site_map.build_tree(b)


# ── summarize ───────────────────────────────────────────────────────────────

def test_summarize_counts_each_group():
    pages = [
        {'url': 'https://e/', 'status': 200},
        {'url': 'https://e/a', 'status': 200},
        {'url': 'https://e/b', 'status': 301},
        {'url': 'https://e/c', 'status': 404},
        {'url': 'https://e/d', 'status': None},
    ]
    s = site_map.summarize(pages)
    assert s == {'2xx': 2, '3xx': 1, '4xx': 1, '5xx': 0, 'err': 1,
                 'total': 5, 'max_depth': 1}


# ── render_html ─────────────────────────────────────────────────────────────

def test_render_html_is_offline_fragment_with_colours():
    pages = [
        {'url': 'https://e/', 'status': 200},
        {'url': 'https://e/admin', 'status': 403},
    ]
    out = site_map.render_html(pages)
    # No external resources — self-contained, offline (invariant I2).
    assert 'http://' not in out and 'https://' not in out
    assert '<script' not in out.lower()
    # Status badges are present and coloured per group.
    assert '200' in out and '403' in out
    assert site_map.classify_status(403)['color'] in out
    # Path segment is shown and HTML-escaped safely.
    assert 'admin' in out


def test_render_html_escapes_path_segments():
    pages = [{'url': 'https://e/<script>x', 'status': 200}]
    out = site_map.render_html(pages)
    assert '<script>x' not in out
    assert '&lt;script&gt;' in out


def test_render_html_empty_input_is_placeholder():
    out = site_map.render_html([])
    assert 'Нет захваченных' in out


# ── capture integration (stubbed fetch, no network) ─────────────────────────

def test_capture_writes_site_map_with_statuses(tmp_path, monkeypatch):
    cap = SiteContentCapture()
    cap.configure('https://ex.com', str(tmp_path / 'cap'), max_pages=5)

    pages = {
        'https://ex.com': (200, '<a href="https://ex.com/ok">o</a>'
                                '<a href="https://ex.com/gone">g</a>', 'text/html'),
        'https://ex.com/ok': (200, '<html>ok</html>', 'text/html'),
        'https://ex.com/gone': (404, None, 'text/html'),  # error page keeps status
    }
    monkeypatch.setattr(cap, '_fetch',
                        lambda url: pages.get(url, (None, None, None)))

    result = cap.run_capture()

    # Result carries the live summary for the GUI.
    summary = result['status_summary']
    assert summary['2xx'] == 2
    assert summary['4xx'] == 1
    assert summary['total'] == 3

    # The 404 is recorded as an error but still appears in the site map.
    assert 'https://ex.com/gone' in result['errors']

    # site_map.json is the persisted, status-bearing tree source.
    data = json.loads((tmp_path / 'cap' / 'site_map.json').read_text('utf-8'))
    by_url = {r['url']: r for r in data}
    assert by_url['https://ex.com/ok']['status'] == 200
    assert by_url['https://ex.com/ok']['file']        # saved page has a file
    assert by_url['https://ex.com/gone']['status'] == 404
    assert 'file' not in by_url['https://ex.com/gone']  # error page, no file
