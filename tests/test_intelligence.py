"""Core Intelligence Framework (core/intelligence.py, EPIC 7) — unit tests.

Confidence / Priority / Explanation are pure over a finding (+ correlation / asset
graph views). No store, no network.
"""

from core import intelligence as intel


def _f(**kw):
    base = {'id': 'f1', 'category': 'vuln', 'rule_id': '', 'title': 't',
            'severity': 'high', 'evidence': {'source': 'nuclei'}}
    base.update(kw)
    return base


# ── confidence ────────────────────────────────────────────────────────────────

def test_confidence_base_by_category():
    assert intel.confidence(_f(category='takeover'))['score'] == 85
    assert intel.confidence(_f(category='vuln'))['score'] == 60
    assert intel.confidence(_f(category='secret', title='Leaked secret: X'))['score'] >= 70


def test_confidence_cve_rule_outranks_vuln_category():
    c = intel.confidence(_f(category='vuln', rule_id='cve-2020-11022'))
    assert c['score'] == 85 and c['band'] == 'high'


def test_confidence_corroboration_bonus_capped():
    one = intel.confidence(_f(category='vuln', evidence={'source': 'nuclei'}))
    two = intel.confidence(_f(category='vuln',
                              evidence={'sources': ['nuclei', 'osv']}))
    many = intel.confidence(_f(category='vuln',
                               evidence={'sources': ['a', 'b', 'c', 'd']}))
    assert two['score'] == one['score'] + 10
    assert many['score'] == one['score'] + 20      # capped at +20


def test_confidence_high_value_secret_bonus():
    generic = intel.confidence(_f(category='secret',
                                  title='Leaked secret: Generic API Key'))
    highval = intel.confidence(_f(category='secret',
                                  title='Leaked secret: AWS Access Key'))
    assert highval['score'] == generic['score'] + 15
    assert highval['band'] == 'high'


def test_confidence_bands():
    assert intel.confidence(_f(category='vuln'))['band'] == 'medium'    # 60
    assert intel.confidence(_f(category='cve', rule_id='cve-1'))['band'] == 'high'


# ── priority ──────────────────────────────────────────────────────────────────

def test_priority_confidence_discounts_severity():
    # Same severity, lower confidence → lower priority.
    hi = intel.priority(_f(severity='high'), 100)
    lo = intel.priority(_f(severity='high'), 60)
    assert hi['score'] > lo['score']
    assert hi['score'] == 35 and lo['score'] == round(35 * 0.6)


def test_priority_exposure_and_sla_bonuses():
    p = intel.priority(_f(severity='high'), 100, clustered=True,
                       sla_bucket='breached')
    assert p['score'] == min(100, 35 + 10 + 10)
    # exposed (not clustered) is a smaller bonus
    p2 = intel.priority(_f(severity='high'), 100, exposed=True)
    assert p2['score'] == 35 + 5


def test_priority_asset_criticality_bonus():
    base = intel.priority(_f(severity='high'), 100)
    hi = intel.priority(_f(severity='high'), 100, criticality_band='high')
    med = intel.priority(_f(severity='high'), 100, criticality_band='medium')
    assert hi['score'] == base['score'] + 10
    assert med['score'] == base['score'] + 5
    # an unknown / low band adds nothing
    assert intel.priority(_f(severity='high'), 100,
                          criticality_band='low')['score'] == base['score']


def test_priority_caps_at_100():
    p = intel.priority(_f(severity='critical'), 100, clustered=True,
                       sla_bucket='breached')
    assert p['score'] == min(100, 50 + 10 + 10) == 70  # critical 50 +10 +10


# ── explanation ────────────────────────────────────────────────────────────────

def test_explain_reuses_knowledge_catalog():
    ex = intel.explain(_f(category='secret', title='Leaked secret: X'))
    assert set(ex) >= {'description', 'impact', 'remediation'}
    assert ex['impact']            # secret has a catalog impact


# ── aggregate ─────────────────────────────────────────────────────────────────

def test_build_ranks_by_priority_with_exposure_and_clusters():
    findings = [
        _f(id='a', severity='medium', category='vuln', evidence={'source': 'x',
           'location': 'a.acme.com/q'}),
        _f(id='b', severity='high', category='cve', rule_id='cve-1',
           evidence={'source': 'osv', 'location': 'b.acme.com/'}),
    ]
    correlation = {'finding_chains': {
        'a': {'host': 'a.acme.com'}, 'b': {'host': 'b.acme.com'}}}
    asset_graph = {'shared_infra': [
        {'type': 'ip', 'node': '1.2.3.4', 'members': ['a.acme.com', 'b.acme.com']}]}
    out = intel.build_intelligence(findings, correlation, asset_graph)
    assert [i['id'] for i in out['items']][0] == 'b'      # high+cve+blast first
    assert out['summary']['findings'] == 2
    assert out['summary']['high_confidence'] == 1         # only the CVE (85)
    assert out['summary']['top_priority'] == out['items'][0]['priority']
    # each item carries confidence + priority + explanation
    top = out['items'][0]
    assert 'confidence_factors' in top and 'priority_factors' in top
    assert 'impact' in top['explanation']


def test_build_intelligence_uses_asset_criticality():
    findings = [_f(id='a', severity='medium', category='vuln',
                   evidence={'source': 'x', 'location': 'a.acme.com/q'})]
    criticality = {'items': [{'value': 'a.acme.com', 'band': 'high',
                              'criticality': 80}]}
    out = intel.build_intelligence(findings, None, None, criticality=criticality)
    top = out['items'][0]
    assert top['asset_criticality'] == 'high'
    # priority gained the +10 high-criticality bonus over the no-criticality build
    plain = intel.build_intelligence(findings)['items'][0]
    assert plain['asset_criticality'] is None
    assert top['priority'] == plain['priority'] + 10


def test_build_empty_is_safe():
    out = intel.build_intelligence([])
    assert out == {'items': [], 'top': [],
                   'summary': {'findings': 0, 'high_confidence': 0,
                               'top_priority': 0}}


def test_build_items_carry_unified_accuracy_fields():
    out = intel.build_intelligence([_f(evidence={'sources': ['nuclei', 'osv'],
                                                 'location': 'a.x.com/q',
                                                 'detail': 'd'})])
    top = out['items'][0]
    assert set(top) >= {'evidence', 'source', 'verification'}
    assert top['source'] == ['nuclei', 'osv']
    assert top['verification'] == 'corroborated'


# ── unified scan accuracy (MODULE 1) ────────────────────────────────────────────

_ACCURACY_KEYS = {'score', 'band', 'factors', 'evidence', 'source', 'verification'}


def test_confidence_for_finding_reuses_confidence():
    f = _f(category='takeover')
    acc = intel.confidence_for('finding', f)
    assert set(acc) >= _ACCURACY_KEYS
    assert acc['score'] == intel.confidence(f)['score'] == 85


def test_confidence_for_technology_method_and_version():
    header_ver = intel.confidence_for('technology', {
        'name': 'Nginx', 'category': 'Server', 'version': '1.25',
        'evidence': 'header:server'})
    assert header_ver['score'] == 95 and header_ver['band'] == 'high'
    assert header_ver['verification'] == 'version-confirmed'
    script_only = intel.confidence_for('technology', {
        'name': 'React', 'category': 'JS Framework', 'version': None,
        'evidence': 'script:react'})
    assert script_only['score'] == 72 and script_only['verification'] == 'exact-match'
    html_only = intel.confidence_for('technology', {
        'name': 'X', 'category': 'Backend', 'evidence': 'html'})
    assert html_only['score'] == 60 and html_only['verification'] == 'heuristic'


def test_confidence_for_cve_cvss_and_multidb():
    enriched = intel.confidence_for('cve', {
        'id': 'CVE-2020-1', 'cvss': 7.5, 'source': 'osv+nvd',
        'published': '2020-01-01'})
    assert enriched['score'] == 100               # 85 + 10 (cvss) + 5 (two dbs)
    assert enriched['verification'] == 'cvss-confirmed'
    assert enriched['source'] == ['nvd', 'osv']
    bare = intel.confidence_for('cve', {'id': 'CVE-1', 'source': 'osv'})
    assert bare['score'] == 85 and bare['verification'] == 'advisory-listed'


def test_confidence_for_asset_probe_vs_tls_only():
    probed = intel.confidence_for('asset', {
        'type': 'subdomain', 'value': 'a.x.com',
        'attrs': {'source': 'subdomains', 'http_status': 200, 'ip': '1.2.3.4'}})
    assert probed['score'] == 93 and probed['verification'] == 'probed'
    tls_only = intel.confidence_for('asset', {
        'type': 'subdomain', 'value': 'b.x.com', 'attrs': {'source': 'ct'}})
    assert tls_only['score'] == 58 and tls_only['verification'] == 'tls-observed'


def test_confidence_for_infrastructure_active_vs_passive():
    active = intel.confidence_for('infrastructure', {
        'ip': '1.2.3.4', 'asn': 'AS13335', 'provider': 'Cloudflare',
        'source': 'asn_intel'})
    assert active['score'] == 88 and active['verification'] == 'active-rdap'
    passive = intel.confidence_for('infrastructure', {'ip': '1.2.3.4', 'asn': 'AS1'})
    assert passive['score'] == 65 and passive['verification'] == 'passive-derive'


def test_confidence_for_api_responded_vs_listed():
    live = intel.confidence_for('api', {'path': '/v1/users', 'method': 'GET',
                                        'status': 200})
    assert live['score'] == 80 and live['verification'] == 'responded'
    listed = intel.confidence_for('api', {'path': '/v1/x'})
    assert listed['score'] == 60 and listed['verification'] == 'listed'


def test_confidence_for_secret_validation_tiers():
    valid_hv = intel.confidence_for('secret', {
        'type': 'AWS Access Key', 'value': 'AKIA' + 'A' * 16})
    assert valid_hv['score'] == 100          # 70 + 20 (valid) + 10 (high-value)
    assert valid_hv['verification'] == 'valid_format'
    placeholder = intel.confidence_for('secret', {
        'type': 'Generic API Key', 'value': 'your_api_key_here'})
    assert placeholder['verification'] == 'invalid_format'
    assert placeholder['score'] < 70         # collapsed by the placeholder penalty
    prevalidated = intel.confidence_for('secret', {
        'type': 'Generic Secret', 'status': 'unverifiable'})
    assert prevalidated['score'] == 70 and prevalidated['verification'] == 'unverifiable'


def test_confidence_for_unknown_type_or_non_dict_is_zeroed():
    assert intel.confidence_for('nope', {})['verification'] == 'unknown'
    assert intel.confidence_for('asset', None)['score'] == 0


def test_build_accuracy_rolls_up_mixed_entities():
    out = intel.build_accuracy({
        'technology': [{'name': 'Nginx', 'version': '1.25',
                        'evidence': 'header:server'}],   # 95
        'cve': [{'id': 'CVE-1', 'source': 'osv'}],       # 85
        'api': [{'path': '/x'}],                          # 60
    })
    assert out['summary']['entities'] == 3
    assert out['summary']['high_confidence'] == 2        # 95 + 85 ≥ 80
    assert out['summary']['by_type'] == {'technology': 1, 'cve': 1, 'api': 1}
    # items are confidence-descending
    assert [i['score'] for i in out['items']] == [95, 85, 60]
    assert out['by_type']['technology']['avg_confidence'] == 95


def test_build_accuracy_empty_is_safe():
    out = intel.build_accuracy({})
    assert out['items'] == [] and out['summary']['entities'] == 0
    assert out['summary']['avg_confidence'] == 0


def test_accuracy_from_report_collects_entities():
    report = {'phases': {
        'recon': {'data': {
            'technologies': [{'name': 'Nginx', 'version': '1.25',
                              'evidence': 'header:server'}],
            'infrastructure': {'ip': '1.2.3.4', 'asn': 'AS13335',
                               'provider': 'Cloudflare', 'source': 'asn_intel'}}},
        'api': {'data': {'keys_found': 1,
                         'details': {'AWS Access Key': ['AKIA' + 'A' * 16]}}},
        'openapi': {'data': {'endpoints': [{'path': '/v1/u', 'method': 'GET'}]}}}}
    findings = [{'id': 'f1', 'category': 'vuln', 'severity': 'high',
                 'title': 't', 'evidence': {'source': 'nuclei'}}]
    assets = [{'id': 'a1', 'type': 'subdomain', 'value': 'a.x.com',
               'attrs': {'source': 'subdomains', 'http_status': 200}}]
    out = intel.accuracy_from_report(report, findings=findings, assets=assets)
    types = set(out['by_type'])
    assert types == {'finding', 'asset', 'technology', 'infrastructure',
                     'secret', 'api'}
    # the AWS key (valid format, high-value) is a high-confidence secret
    sec = out['by_type']['secret']['items'][0]
    assert sec['verification'] == 'valid_format' and sec['score'] == 100
    assert out['summary']['entities'] == 6


def test_accuracy_from_report_empty_report_is_safe():
    out = intel.accuracy_from_report({})
    assert out['summary']['entities'] == 0


# ── asset criticality (EPIC 9) ──────────────────────────────────────────────────

def test_asset_criticality_type_weight_and_band():
    dom = intel.asset_criticality({'type': 'domain', 'value': 'x.com', 'attrs': {}})
    assert dom['score'] == 40 and dom['band'] == 'medium'
    tech = intel.asset_criticality({'type': 'technology', 'value': 'React',
                                    'attrs': {}})
    assert tech['band'] == 'low'


def test_asset_criticality_blast_radius_and_findings():
    c = intel.asset_criticality({'type': 'ip', 'value': '1.2.3.4', 'attrs': {}},
                                dependents=12, findings={'count': 3, 'worst': 'high'})
    assert c['score'] == 79 and c['band'] == 'high'   # 30 + 30 + (15 + 4)


def test_asset_criticality_takeover_and_reachable():
    takeover = intel.asset_criticality({'type': 'subdomain', 'value': 'a.x.com',
                                        'attrs': {'takeover': True}})
    assert takeover['score'] == 42                     # 22 + 20
    reachable = intel.asset_criticality({'type': 'subdomain', 'value': 'b.x.com',
                                         'attrs': {'http_status': 200}})
    assert reachable['score'] == 27                    # 22 + 5


def test_build_asset_criticality_ranks_with_blast_radius():
    assets = [
        {'id': 'd', 'type': 'domain', 'value': 'x.com', 'attrs': {}},
        {'id': 'ip1', 'type': 'ip', 'value': '1.2.3.4', 'attrs': {}},
        {'id': 's1', 'type': 'subdomain', 'value': 'a.x.com',
         'attrs': {'ip': '1.2.3.4'}},
        {'id': 's2', 'type': 'subdomain', 'value': 'b.x.com',
         'attrs': {'ip': '1.2.3.4'}},
    ]
    asset_graph = {'graph': {'edges': [
        {'src': 's1', 'dst': 'ip1', 'rel': 'resolves'},
        {'src': 's2', 'dst': 'ip1', 'rel': 'resolves'}]},
        'shared_infra': [{'type': 'ip', 'node': '1.2.3.4',
                          'members': ['a.x.com', 'b.x.com'], 'count': 2}]}
    correlation = {
        'asset_findings': {'s1': {'findings': [{'severity': 'high'}],
                                  'worst': 'high'}},
        'infra_exposure': [{'type': 'ip', 'node': '1.2.3.4',
                            'findings_count': 1, 'worst': 'high'}]}
    out = intel.build_asset_criticality(assets, correlation, asset_graph)
    assert out['summary']['assets'] == 4
    top = out['items'][0]
    assert top['id'] == 'ip1' and top['criticality'] == 55   # 30 + 10 + 15
    assert out['summary']['top_criticality'] == 55


def test_build_asset_criticality_empty_is_safe():
    out = intel.build_asset_criticality([])
    assert out == {'items': [], 'top': [],
                   'summary': {'assets': 0, 'high_criticality': 0,
                               'top_criticality': 0}}


# ── asset exposure (likelihood axis) ────────────────────────────────────────────

def test_exposure_score_has_no_type_weight():
    # Unlike criticality, a bare domain with no exposure signal scores 0 — exposure
    # is likelihood, not asset value.
    dom = intel.exposure_score({'type': 'domain', 'value': 'x.com', 'attrs': {}})
    assert dom['score'] == 0 and dom['band'] == 'low'


def test_exposure_score_reachability_tiers():
    takeover = intel.exposure_score({'type': 'subdomain', 'attrs': {'takeover': True}})
    assert takeover['score'] == 35
    reachable = intel.exposure_score({'type': 'subdomain',
                                      'attrs': {'http_status': 200}})
    assert reachable['score'] == 20
    resolved = intel.exposure_score({'type': 'subdomain', 'attrs': {'ip': '1.2.3.4'}})
    assert resolved['score'] == 5


def test_exposure_score_findings_and_blast():
    x = intel.exposure_score({'type': 'subdomain', 'attrs': {'http_status': 200}},
                             dependents=2, findings={'count': 3, 'worst': 'critical'})
    # 20 (reachable) + (30 + min(10, 4)) findings + min(20, 2*5) blast = 64
    assert x['score'] == 20 + 34 + 10 and x['band'] == 'high'


def test_exposure_score_cluster_size_as_blast():
    # A member of a 4-host cluster inherits blast radius (cluster_size - 1).
    x = intel.exposure_score({'type': 'subdomain', 'attrs': {}},
                             dependents=0, cluster_size=4)
    assert x['score'] == min(20, 3 * 5)   # 15


def test_build_exposure_ranks_and_summary():
    assets = [
        {'id': 'd', 'type': 'domain', 'value': 'x.com', 'attrs': {}},
        {'id': 's1', 'type': 'subdomain', 'value': 'a.x.com',
         'attrs': {'http_status': 200, 'ip': '1.2.3.4'}},
        {'id': 's2', 'type': 'subdomain', 'value': 'b.x.com',
         'attrs': {'ip': '1.2.3.4'}},
    ]
    asset_graph = {'shared_infra': [{'type': 'ip', 'node': '1.2.3.4',
                                     'members': ['a.x.com', 'b.x.com'], 'count': 2}]}
    correlation = {'asset_findings': {'s1': {'findings': [{'severity': 'critical'}],
                                             'worst': 'critical'}}}
    out = intel.build_exposure(assets, correlation, asset_graph)
    assert out['summary']['assets'] == 3
    top = out['items'][0]
    # s1: 20 reachable + 30 critical-finding + 5 blast (cluster of 2 → 1) = 55
    assert top['id'] == 's1' and top['exposure'] == 55 and top['band'] == 'medium'
    assert out['summary']['top_exposure'] == 55
    # the bare domain with no exposure signal sinks to the bottom at 0
    assert out['items'][-1]['exposure'] == 0


def test_build_exposure_empty_is_safe():
    out = intel.build_exposure([])
    assert out == {'items': [], 'top': [],
                   'summary': {'assets': 0, 'exposed_assets': 0,
                               'top_exposure': 0}}


# ── attack paths (EPIC 11) ──────────────────────────────────────────────────────

def test_build_attack_paths_lateral_over_shared_infra():
    correlation = {'exposure': [{'value': 'a.x.com', 'worst': 'critical',
                                 'findings_count': 2}]}
    asset_graph = {'shared_infra': [{'type': 'ip', 'node': '1.2.3.4',
                                     'members': ['a.x.com', 'b.x.com', 'c.x.com'],
                                     'count': 3}]}
    criticality = {'items': [{'value': 'b.x.com', 'band': 'high'},
                             {'value': 'c.x.com', 'band': 'medium'}]}
    out = intel.build_attack_paths(correlation, asset_graph, criticality)
    assert out['summary']['paths'] == 1
    p = out['paths'][0]
    assert p['entry'] == 'a.x.com' and p['entry_severity'] == 'critical'
    assert p['pivot_type'] == 'ip' and p['pivot_node'] == '1.2.3.4'
    assert sorted(p['targets']) == ['b.x.com', 'c.x.com']
    assert p['critical_targets'] == 1
    assert p['score'] == 41 and p['band'] == 'medium'   # 30 + min(20,6) + 5


def test_build_attack_paths_needs_a_finding_bearing_entry():
    # cluster exists but no member carries a finding → no path
    asset_graph = {'shared_infra': [{'type': 'ip', 'node': '1.2.3.4',
                                     'members': ['a.x.com', 'b.x.com'],
                                     'count': 2}]}
    out = intel.build_attack_paths({'exposure': []}, asset_graph, {})
    assert out['summary']['paths'] == 0


def test_build_attack_paths_empty_is_safe():
    out = intel.build_attack_paths()
    assert out == {'paths': [], 'top': [],
                   'summary': {'paths': 0, 'critical_paths': 0, 'top_score': 0}}


# ── EPIC NEXT F2 — Business-Aware Prioritization ──────────────────────────────

def test_threat_tier_classification():
    assert intel._threat_tier({'category': 'takeover'}) == 'high'
    assert intel._threat_tier({'category': 'secret'}) == 'high'
    assert intel._threat_tier({'category': 'vuln', 'rule_id': 'sqli-detect'}) == 'high'
    assert intel._threat_tier({'category': 'vuln', 'rule_id': 'cve-2021-1'}) == 'medium'
    assert intel._threat_tier({'category': 'graphql'}) == 'medium'
    assert intel._threat_tier({'category': 'header', 'rule_id': 'x'}) is None


def test_priority_threat_bonus():
    f = {'severity': 'medium'}
    base = intel.priority(f, 100)['score']
    hi = intel.priority(f, 100, threat_tier='high')
    assert hi['score'] == base + 10
    assert any('эксплуатируем' in x['factor'].lower() for x in hi['factors'])
    assert intel.priority(f, 100, threat_tier='medium')['score'] == base + 5
    # No tier → byte-identical to the pre-F2 result (no extra factor).
    assert intel.priority(f, 100, threat_tier=None) == intel.priority(f, 100)


def test_build_intelligence_carries_threat_tier():
    item = intel.build_intelligence([{'id': 't', 'title': 'Subdomain takeover',
                                      'severity': 'high', 'category': 'takeover',
                                      'evidence': {}}])['items'][0]
    assert item['threat'] == 'high'
    assert any('эксплуатируем' in x['factor'].lower()
               for x in item['priority_factors'])


def test_business_context_raises_finding_priority():
    """Business criticality / data sensitivity reach finding priority through the
    (business-aware) criticality band — the F2 end-to-end path."""
    from core.asset_adapter import asset_fingerprint
    assets = [{'id': 'subdomain:shop.site.com', 'type': 'subdomain',
               'value': 'shop.site.com', 'attrs': {}}]
    # Stored findings carry a scheme-stripped, host-matchable location.
    finding = {'id': 'f1', 'title': 'Missing header', 'severity': 'medium',
               'category': 'header', 'evidence': {'location': 'shop.site.com/'}}

    plain_crit = intel.build_asset_criticality(assets)
    plain = intel.build_intelligence([finding],
                                     criticality=plain_crit)['items'][0]['priority']

    fp = asset_fingerprint('subdomain', 'shop.site.com')
    biz = {'assets': {fp: {'criticality': 'critical',
                           'data_sensitivity': 'restricted'}}}
    boosted_crit = intel.build_asset_criticality(assets, business=biz)
    boosted = intel.build_intelligence([finding],
                                       criticality=boosted_crit)['items'][0]['priority']
    assert boosted > plain   # the declared business importance lifted its priority
