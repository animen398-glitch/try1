"""Attack Surface graph — category extraction and offline SVG render."""

import re

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


def test_build_surface_includes_subdomains_when_phase_ran():
    report = _report(subdomains={'data': {'results': [
        {'subdomain': 'a.ex.com'}, {'subdomain': 'b.ex.com'}]}})
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['Subdomains']['count'] == 2
    assert set(names['Subdomains']['items']) == {'a.ex.com', 'b.ex.com'}


def test_build_surface_takeovers_are_own_category_and_kept_in_subdomains():
    # A takeover host is breadth (Subdomains) AND a critical exposure (Takeovers);
    # both dimensions count. A clean host stays only in Subdomains.
    report = _report(subdomains={'data': {
        'results': [{'subdomain': 'bad.ex.com'}, {'subdomain': 'ok.ex.com'}],
        'summary': {'takeover_candidates': ['bad.ex.com']}}})
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['Takeovers']['items'] == ['bad.ex.com']
    assert set(names['Subdomains']['items']) == {'bad.ex.com', 'ok.ex.com'}


def test_build_surface_omits_takeovers_when_none():
    report = _report(subdomains={'data': {
        'results': [{'subdomain': 'ok.ex.com'}], 'summary': {}}})
    names = [c['name'] for c in asf.build_surface(report)['categories']]
    assert 'Takeovers' not in names


def test_build_surface_includes_leaking_source_maps():
    # Only maps that exposed original source (has_content) are surfaced — a map
    # without content is not a leak and stays off the graph.
    report = _report(security={'data': {'source_maps': [
        {'url': 'https://ex.com/app.js.map', 'has_content': True},
        {'url': 'https://ex.com/vendor.js.map', 'has_content': False}]}})
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['Source Maps']['count'] == 1
    assert names['Source Maps']['items'] == ['https://ex.com/app.js.map']


def test_build_surface_includes_reachable_graphql():
    report = _report(security={'data': {'graphql': [
        {'url': 'https://ex.com/graphql', 'graphql': True, 'introspection': True},
        {'url': 'https://ex.com/v2', 'graphql': True, 'introspection': False},
        {'url': 'https://ex.com/none', 'graphql': False}]}})   # not reachable
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['GraphQL']['count'] == 2
    assert 'https://ex.com/graphql [introspection]' in names['GraphQL']['items']
    assert 'https://ex.com/v2' in names['GraphQL']['items']


def test_findings_category_excludes_source_map_graphql_and_cookies():
    # Source-map / GraphQL / weak-cookie / takeover exposures are their own
    # categories; the same findings folded into the vuln phase must NOT also
    # appear in the generic Findings category, or they'd double the surface score.
    report = _report(
        security={'data': {
            'source_maps': [{'url': 'https://ex.com/app.js.map',
                             'has_content': True}],
            'graphql': [{'url': 'https://ex.com/graphql', 'graphql': True,
                         'introspection': True}]}},
        cookies={'data': {'cookies': [{'name': 'sid', 'verdict': 'Weak'}]}},
        subdomains={'data': {'results': [{'subdomain': 'bad.ex.com'}],
                             'summary': {'takeover_candidates': ['bad.ex.com']}}},
        vulns={'summary': {}, 'findings': [
            {'title': 'Source map exposes original source',
             'category': 'sourcemap'},
            {'title': 'GraphQL introspection enabled', 'category': 'graphql'},
            {'title': "Weakly protected cookie: sid", 'category': 'cookie'},
            {'title': 'Subdomain takeover possible: bad.ex.com',
             'category': 'takeover'},
            {'title': 'Leaked secret: AWS Access Key', 'category': 'secret'},
            {'title': 'Exposed .env'}]})   # only this is a generic finding
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['Findings']['items'] == ['Exposed .env']
    assert names['Source Maps']['count'] == 1
    assert names['GraphQL']['count'] == 1
    assert names['Weak Cookies']['count'] == 1
    assert names['Takeovers']['count'] == 1


def test_build_surface_includes_weak_cookies_only():
    # Only cookies the audit scored Weak are attack surface; strong/moderate
    # ones (a proper Set-Cookie) stay off the graph.
    report = _report(cookies={'data': {'cookies': [
        {'name': 'sid', 'verdict': 'Weak'},
        {'name': 'csrf', 'verdict': 'Strong'},
        {'name': 'pref', 'verdict': 'Moderate'}]}})
    names = {c['name']: c for c in asf.build_surface(report)['categories']}
    assert names['Weak Cookies']['count'] == 1
    assert names['Weak Cookies']['items'] == ['sid']


def test_build_surface_omits_weak_cookies_when_none_weak():
    report = _report(cookies={'data': {'cookies': [
        {'name': 'sid', 'verdict': 'Strong'}]}})
    names = [c['name'] for c in asf.build_surface(report)['categories']]
    assert 'Weak Cookies' not in names


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

# ── surface_score / score_band ──────────────────────────────────────────────

def test_surface_score_weights_risk_categories():
    surface = {'categories': [
        {'name': 'Secrets', 'count': 2},        # 2 × 5 = 10
        {'name': 'Technologies', 'count': 3},   # 3 × 1 = 3
        {'name': 'Findings', 'count': 1},        # 1 × 3 = 3
        {'name': 'Source Maps', 'count': 1},     # 1 × 3 = 3
        {'name': 'GraphQL', 'count': 1},         # 1 × 3 = 3
        {'name': 'Weak Cookies', 'count': 2},    # 2 × 2 = 4
        {'name': 'Takeovers', 'count': 1},       # 1 × 5 = 5 (top tier)
    ]}
    assert asf.surface_score(surface) == 31


def test_surface_score_empty_is_zero():
    assert asf.surface_score({'categories': []}) == 0
    assert asf.surface_score({}) == 0


def test_score_band_thresholds():
    assert asf.score_band(0) == 'Minimal'
    assert asf.score_band(3) == 'Low'
    assert asf.score_band(10) == 'Medium'
    assert asf.score_band(25) == 'High'
    assert asf.score_band(40) == 'Critical'


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


# ── render_interactive (offline CSS interactivity, no JS) ───────────────────

def _interactive_surface():
    return asf.build_surface(_report(
        recon={'data': {'cms': ['React']}},
        api={'data': {'details': {'AWS Key': ['x']}}},
        capture={'data': {'site_map': [{'url': 'https://ex.com/a'}]}},
        vulns={'findings': [{'title': 'Exposed .env'}]}))


def test_render_interactive_is_offline_no_js():
    out = asf.render_interactive(_interactive_surface())
    # Interactivity is pure CSS — never any script or *loaded* external resource.
    # (Page URLs may appear as text/tooltip data; that is content, not a load.)
    assert '<script' not in out.lower()
    assert 'src=' not in out
    assert '<link' not in out.lower()
    assert 'url(' not in out                       # no CSS-loaded resource
    # The only hrefs are internal fragment anchors (#as-…), nothing external.
    hrefs = re.findall(r'href="([^"]*)"', out)
    assert hrefs and all(h.startswith('#as-') for h in hrefs)
    # CSS click + hover hooks are present.
    assert '.as-panel:target{display:block;}' in out
    assert 'a:hover .as-node rect' in out


def test_render_interactive_links_nodes_to_panels():
    out = asf.render_interactive(_interactive_surface())
    # Every node anchor has a matching panel element with the same id.
    for slug in ('technologies', 'secrets', 'pages', 'findings'):
        assert f'href="#as-{slug}"' in out
        assert f'id="as-{slug}"' in out


def test_render_interactive_panel_lists_items_and_overflow():
    surface = {'domain': 'ex.com', 'categories': [
        {'name': 'Pages', 'color': '#2e7d32', 'count': 50,
         'items': [f'/p{i}' for i in range(10)]}]}
    out = asf.render_interactive(surface)
    assert '<li>/p0</li>' in out
    # count (50) exceeds shown items (10) → an overflow line, not 50 <li>.
    assert 'ещё 40' in out


def test_render_interactive_escapes_and_slugs():
    surface = {'domain': '<x>', 'categories': [
        {'name': 'Source Maps', 'color': '#ad1457', 'count': 1,
         'items': ['<img>']}]}
    out = asf.render_interactive(surface)
    assert 'id="as-source-maps"' in out          # multiword name slugged
    assert '&lt;img&gt;' in out                   # item escaped in the panel
    assert '&lt;x&gt;' in out                     # domain escaped


def test_render_interactive_empty_is_placeholder():
    out = asf.render_interactive({'domain': 'ex.com', 'categories': []})
    assert '<svg' not in out
    assert 'Недостаточно данных' in out
