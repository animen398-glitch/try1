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


def test_build_empty_is_safe():
    out = intel.build_intelligence([])
    assert out == {'items': [], 'top': [],
                   'summary': {'findings': 0, 'high_confidence': 0,
                               'top_priority': 0}}
