"""Attack Surface graph — category extraction and offline SVG render."""

from core import attack_surface as asf


def _report(**phases):
    return {'domain': 'ex.com', 'phases': phases}


# ── build_surface ───────────────────────────────────────────────────────────

def test_build_surface_extracts_present_categories():
    report = _report(
        recon={'data': {'ip': '1.2.3.4', 'cms': ['React', 'Nginx']}},
        api={'data': {'keys_found': 2,
                      'details': {'AWS Key': ['x'], 'Stripe': ['y']}}},
        capture={'data': {'site_map': [{'url': 'https://ex.com/'},
                                       {'url': 'https://ex.com/a'}]}},
        vulns={'summary': {}, 'findings': [{'title': 'Exposed .env'}]},
    )
    surface = asf.build_surface(report)
    names = {c['name']: c for c in surface['categories']}
    assert surface['domain'] == 'ex.com'
    assert names['Technologies']['count'] == 2
    assert names['Technologies']['items'] == ['React', 'Nginx']
    assert names['Infrastructure']['items'] == ['1.2.3.4']
    # Secrets surface their *types*, not raw values.
    assert set(names['Secrets']['items']) == {'AWS Key', 'Stripe'}
    assert names['Pages']['count'] == 2
    assert names['Findings']['items'] == ['Exposed .env']


def test_build_surface_merges_technologies_and_infra_chain():
    report = _report(recon={'data': {
        'ip': '1.2.3.4',
        'cms': ['React'],
        'technologies': [
            {'name': 'Nginx', 'category': 'Server', 'version': '1.25'},
            {'name': 'React', 'category': 'JS'},   # dup of cms, dropped
        ],
        'infrastructure': {'asn': 'AS13335', 'asn_name': 'Cloudflare',
                           'provider': 'Cloudflare'},
    }})
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['Technologies']['items'] == ['React', 'Nginx 1.25']
    assert names['Infrastructure']['items'] == [
        '1.2.3.4', 'AS13335 Cloudflare', 'Cloudflare']


def test_build_surface_omits_empty_categories():
    surface = asf.build_surface(_report(recon={'data': {'cms': ['Vue']}}))
    names = [c['name'] for c in surface['categories']]
    assert names == ['Technologies']          # nothing else had data


def test_build_surface_secrets_count_fallback():
    # Only a count is available (no per-type details).
    surface = asf.build_surface(_report(api={'data': {'keys_found': 3}}))
    secrets = next(c for c in surface['categories'] if c['name'] == 'Secrets')
    assert secrets['items'] == ['3 keys']


def test_build_surface_empty_report():
    surface = asf.build_surface({'phases': {}})
    assert surface['categories'] == []
    assert surface['domain'] == 'target'


def test_build_surface_caps_items():
    pages = [{'url': f'https://ex.com/{i}'} for i in range(50)]
    surface = asf.build_surface(_report(capture={'data': {'site_map': pages}}))
    pages_cat = next(c for c in surface['categories'] if c['name'] == 'Pages')
    assert pages_cat['count'] == 50                # count is the true total
    assert len(pages_cat['items']) == asf._MAX_ITEMS   # but items are capped


# ── render_svg ──────────────────────────────────────────────────────────────

def test_render_svg_is_offline_inline():
    surface = asf.build_surface(_report(
        recon={'data': {'cms': ['React']}},
        vulns={'findings': [{'title': 'X'}]}))
    out = asf.render_svg(surface)
    assert out.startswith('<svg')
    assert '<script' not in out.lower()
    # No external resources of any kind.
    assert 'http://' not in out and 'https://' not in out
    assert 'src=' not in out and 'href=' not in out
    # Domain + category nodes are drawn with connecting spokes.
    assert 'ex.com' in out
    assert 'Technologies (1)' in out
    assert '<line' in out


def test_render_svg_escapes_text():
    surface = {'domain': '<x>', 'categories': [
        {'name': 'Findings', 'color': '#f00', 'count': 1, 'items': ['<img>']}]}
    out = asf.render_svg(surface)
    assert '<x>' not in out.replace('<svg', '')   # domain escaped
    assert '&lt;x&gt;' in out
    assert '&lt;img&gt;' in out                    # item (in <title>) escaped


def test_render_svg_empty_is_placeholder():
    out = asf.render_svg({'domain': 'ex.com', 'categories': []})
    assert '<svg' not in out
    assert 'Недостаточно данных' in out
