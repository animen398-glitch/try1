"""Advanced technology fingerprint — offline signature engine + render."""

from core import tech_fingerprint as tf


def _names(techs):
    return {t['name'] for t in techs}


# ── fingerprint: header-driven CDN / infra ──────────────────────────────────

def test_fingerprint_cloudflare_via_header_present():
    techs = tf.fingerprint(headers={'CF-Ray': 'abc', 'Server': 'cloudflare'})
    cf = next(t for t in techs if t['name'] == 'Cloudflare')
    assert cf['category'] == 'CDN'


def test_fingerprint_fastly_via_via_header():
    techs = tf.fingerprint(headers={'Via': '1.1 varnish, 1.1 fastly'})
    assert 'Fastly' in _names(techs)


# ── version extraction ──────────────────────────────────────────────────────

def test_fingerprint_extracts_server_version():
    techs = tf.fingerprint(headers={'Server': 'nginx/1.25.3'})
    nginx = next(t for t in techs if t['name'] == 'Nginx')
    assert nginx['version'] == '1.25.3'
    assert nginx['category'] == 'Server'


def test_fingerprint_extracts_php_version():
    techs = tf.fingerprint(headers={'X-Powered-By': 'PHP/8.2.1'})
    php = next(t for t in techs if t['name'] == 'PHP')
    assert php['version'] == '8.2.1'


def test_fingerprint_no_version_when_absent():
    techs = tf.fingerprint(headers={'Server': 'nginx'})
    nginx = next(t for t in techs if t['name'] == 'Nginx')
    assert nginx['version'] is None


# ── cookie-driven backend frameworks ────────────────────────────────────────

def test_fingerprint_laravel_via_cookie():
    techs = tf.fingerprint(headers={'Set-Cookie': 'laravel_session=eyJ; Path=/'})
    laravel = next(t for t in techs if t['name'] == 'Laravel')
    assert laravel['category'] == 'Backend'
    assert laravel['evidence'].startswith('cookie:')


def test_fingerprint_django_via_cookie():
    techs = tf.fingerprint(headers={'Set-Cookie': 'csrftoken=abc; sessionid=x'})
    assert 'Django' in _names(techs)


# ── script / html driven analytics ──────────────────────────────────────────

def test_fingerprint_google_analytics_via_script():
    techs = tf.fingerprint(
        scripts=['https://www.googletagmanager.com/gtag/js?id=G-ABC'])
    ga = next(t for t in techs if t['name'] == 'Google Analytics')
    assert ga['category'] == 'Analytics'


def test_fingerprint_hotjar_via_inline_html():
    techs = tf.fingerprint(html='window._hjSettings={hjid:123};')
    assert 'Hotjar' in _names(techs)


# ── JS meta-frameworks (D1) ─────────────────────────────────────────────────

def test_fingerprint_nextjs_via_html_marker():
    techs = tf.fingerprint(html='<div id="__next"></div><script>__NEXT_DATA__={}')
    nx = next(t for t in techs if t['name'] == 'Next.js')
    assert nx['category'] == 'JS Framework'


def test_fingerprint_nextjs_via_powered_by_header():
    techs = tf.fingerprint(headers={'X-Powered-By': 'Next.js'})
    assert 'Next.js' in _names(techs)


def test_fingerprint_nuxt_via_script_path():
    techs = tf.fingerprint(scripts=['/_nuxt/entry.abc.js'])
    assert 'Nuxt.js' in _names(techs)


def test_fingerprint_sveltekit_via_html():
    techs = tf.fingerprint(html='<body data-sveltekit-preload-data="hover">')
    assert 'SvelteKit' in _names(techs)


def test_fingerprint_gatsby_via_script_path():
    techs = tf.fingerprint(scripts=['/page-data/index/page-data.json'])
    assert 'Gatsby' in _names(techs)


def test_fingerprint_remix_and_astro_via_html():
    assert 'Remix' in _names(tf.fingerprint(html='window.__remixContext = {};'))
    assert 'Astro' in _names(tf.fingerprint(html='<astro-island uid="1">'))


def test_fingerprint_angular_extracts_version_from_html():
    techs = tf.fingerprint(html='<app-root ng-version="17.0.6"></app-root>')
    ng = next(t for t in techs if t['name'] == 'Angular')
    assert ng['category'] == 'JS Framework'
    assert ng['version'] == '17.0.6'
    assert ng['evidence'] == 'html'


# ── ordering, dedup, empties ────────────────────────────────────────────────

def test_fingerprint_sorted_by_category_then_name():
    techs = tf.fingerprint(headers={
        'Server': 'nginx', 'X-Powered-By': 'PHP/8',
        'CF-Ray': 'x', 'Set-Cookie': 'laravel_session=1',
    })
    cats = [t['category'] for t in techs]
    # CDN before Server before Backend before Language (CATEGORY_ORDER).
    assert cats == sorted(cats, key=tf.CATEGORY_ORDER.index)


def test_fingerprint_empty_input_is_empty():
    assert tf.fingerprint() == []
    assert tf.fingerprint(headers={}, html='', scripts=[]) == []


def test_fingerprint_dedup_single_entry_per_tech():
    # Two signals for the same tech still yield one entry.
    techs = tf.fingerprint(
        headers={'Server': 'cloudflare', 'CF-Ray': 'x'})
    assert sum(1 for t in techs if t['name'] == 'Cloudflare') == 1


# ── extract_script_srcs ─────────────────────────────────────────────────────

def test_extract_script_srcs():
    html = ('<script src="/a.js"></script><script>inline()</script>'
            "<script src='https://cdn/x.js' defer></script>")
    assert tf.extract_script_srcs(html) == ['/a.js', 'https://cdn/x.js']


def test_extract_script_srcs_empty():
    assert tf.extract_script_srcs('') == []
    assert tf.extract_script_srcs(None) == []


# ── render_html (offline) ───────────────────────────────────────────────────

def test_render_html_groups_and_is_offline():
    techs = tf.fingerprint(headers={'Server': 'nginx/1.25', 'CF-Ray': 'x'})
    out = tf.render_html(techs)
    assert '<script' not in out.lower()
    assert 'http://' not in out and 'https://' not in out
    assert 'Nginx 1.25' in out
    assert 'Cloudflare' in out


def test_render_html_escapes():
    out = tf.render_html([{'name': '<x>', 'category': 'CDN', 'version': None}])
    assert '&lt;x&gt;' in out
    assert '<x>' not in out


def test_render_html_empty_placeholder():
    out = tf.render_html([])
    assert 'не определены' in out
    assert '<span' not in out
