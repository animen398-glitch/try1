"""Cross-entity correlation core (core/correlation.py, Epic F-K1) — offline.

Pure aggregator tests over hand-built store rows, plus a store-backed
integration via the conftest-isolated findings/assets DBs.
"""

from core.correlation import build_correlation, load_correlation


def _asset(aid, atype, value, label='', **attrs):
    return {'id': aid, 'type': atype, 'value': value, 'label': label or value,
            'status': 'ACTIVE', 'attrs': attrs}


def _finding(fid, location, severity='info', title='x'):
    return {'id': fid, 'project': 'p', 'severity': severity, 'title': title,
            'status': 'OPEN', 'evidence': {'location': location}}


def _infra_assets():
    return [
        _asset('a-dom', 'domain', 'acme.com'),
        _asset('a-sub', 'subdomain', 'api.acme.com', ip='1.2.3.4'),
        _asset('a-ip', 'ip', '1.2.3.4', asn='AS13335'),
        _asset('a-asn', 'asn', 'AS13335', label='AS13335 Cloudflare',
               name='Cloudflare', provider='Cloudflare'),
        _asset('a-ep', 'endpoint', 'api.acme.com/graphql'),
    ]


# ── join + chain ──────────────────────────────────────────────────────────────

def test_endpoint_finding_resolves_full_chain():
    findings = [_finding('f1', 'api.acme.com/graphql', 'critical')]
    out = build_correlation(findings, _infra_assets())
    chain = out['finding_chains']['f1']
    assert chain['endpoint'] == 'api.acme.com/graphql'
    assert chain['host'] == 'api.acme.com'
    assert chain['ip'] == '1.2.3.4'
    assert chain['asn'] == 'AS13335'
    assert chain['asn_name'] == 'Cloudflare'
    # Attached to the most specific asset (the endpoint).
    assert 'a-ep' in out['asset_findings']
    assert out['asset_findings']['a-ep']['worst'] == 'critical'


def test_apex_domain_finding_resolves_chain():
    # F-K5: a finding on the apex domain resolves ip/asn via the domain asset's
    # own attrs (parity with subdomains).
    assets = [
        _asset('a-dom', 'domain', 'acme.com', ip='9.9.9.9'),
        _asset('a-ip', 'ip', '9.9.9.9', asn='AS100'),
        _asset('a-asn', 'asn', 'AS100', name='Acme ISP', provider='Acme ISP'),
    ]
    out = build_correlation([_finding('f', 'acme.com', 'high')], assets)
    chain = out['finding_chains']['f']
    assert chain['host'] == 'acme.com'
    assert chain['ip'] == '9.9.9.9' and chain['asn'] == 'AS100'
    assert chain['asn_name'] == 'Acme ISP'


def test_chain_resolves_netblock_containment():
    # F-K6: the finding's IP is matched into its most specific netblock (CIDR).
    assets = _infra_assets() + [
        _asset('a-nb1', 'netblock', '1.2.0.0/16'),
        _asset('a-nb2', 'netblock', '1.2.3.0/24'),   # tighter → should win
    ]
    out = build_correlation([_finding('f', 'api.acme.com/graphql', 'high')],
                            assets)
    assert out['finding_chains']['f']['netblock'] == '1.2.3.0/24'


def test_chain_no_netblock_when_ip_outside():
    assets = _infra_assets() + [_asset('a-nb', 'netblock', '10.0.0.0/8')]
    out = build_correlation([_finding('f', 'api.acme.com/graphql', 'high')],
                            assets)
    assert 'netblock' not in out['finding_chains']['f']   # 1.2.3.4 ∉ 10/8


def test_host_level_finding_attaches_to_subdomain():
    findings = [_finding('f2', 'api.acme.com', 'high')]
    out = build_correlation(findings, _infra_assets())
    assert 'a-sub' in out['asset_findings']
    assert out['asset_findings']['a-sub']['severity_counts']['high'] == 1
    # Chain resolves the infra even without an endpoint.
    assert out['finding_chains']['f2']['ip'] == '1.2.3.4'
    assert 'endpoint' not in out['finding_chains']['f2']


def test_unlocated_finding_is_uncorrelated():
    findings = [_finding('f3', '', 'medium')]
    out = build_correlation(findings, _infra_assets())
    assert out['finding_chains']['f3'] == {}
    assert out['asset_findings'] == {}
    assert out['summary']['correlated'] == 0
    assert out['summary']['uncorrelated'] == 1


# ── exposure roll-up ──────────────────────────────────────────────────────────

def test_exposure_rolls_endpoint_findings_up_to_host():
    findings = [
        _finding('f1', 'api.acme.com/graphql', 'critical'),  # on endpoint
        _finding('f2', 'api.acme.com', 'high'),              # on host
    ]
    out = build_correlation(findings, _infra_assets())
    exposure = out['exposure']
    api = next(r for r in exposure if r['value'] == 'api.acme.com')
    assert api['findings_count'] == 2          # endpoint + host findings folded
    assert api['worst'] == 'critical'
    assert api['severity_counts']['critical'] == 1
    assert api['severity_counts']['high'] == 1
    # The clean domain has no findings → not listed.
    assert all(r['value'] != 'acme.com' for r in exposure)


def test_exposure_dedups_finding_counted_once():
    # A finding matching both an endpoint and (via host) should count once.
    findings = [_finding('f1', 'api.acme.com/graphql', 'critical')]
    out = build_correlation(findings, _infra_assets())
    api = next(r for r in out['exposure'] if r['value'] == 'api.acme.com')
    assert api['findings_count'] == 1


def test_exposure_sorted_worst_first():
    assets = _infra_assets() + [_asset('a-sub2', 'subdomain', 'cdn.acme.com')]
    findings = [
        _finding('f1', 'cdn.acme.com', 'low'),
        _finding('f2', 'api.acme.com', 'critical'),
    ]
    out = build_correlation(findings, assets)
    assert [r['value'] for r in out['exposure']] == ['api.acme.com', 'cdn.acme.com']


def test_summary_counts():
    findings = [
        _finding('f1', 'api.acme.com/graphql', 'critical'),
        _finding('f2', 'api.acme.com', 'high'),
        _finding('f3', '', 'info'),
    ]
    out = build_correlation(findings, _infra_assets())
    assert out['summary']['findings'] == 3
    assert out['summary']['correlated'] == 2
    assert out['summary']['severity_counts']['critical'] == 1
    assert out['summary']['exposed_assets'] == 1


def test_empty_inputs():
    out = build_correlation([], [])
    assert out['exposure'] == [] and out['asset_findings'] == {}
    assert out['summary']['findings'] == 0


# ── store-backed loader ───────────────────────────────────────────────────────

def test_load_correlation_reads_stores():
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore

    fstore = FindingsStore()
    # Raw scanner finding — the adapter derives the location from 'location'.
    fstore.sync('p', 's1', [{
        'category': 'graphql', 'title': 'GraphQL introspection',
        'severity': 'high', 'location': 'https://api.acme.com/graphql'}])
    AssetStore().sync('p', 's1', [
        Asset('subdomain', 'api.acme.com', attrs={'ip': '1.2.3.4'}),
        Asset('endpoint', 'api.acme.com/graphql')])

    out = load_correlation('p')
    assert 'error' not in out
    # The high finding correlated to the endpoint asset.
    assert out['summary']['correlated'] == 1
    api = next(r for r in out['exposure'] if r['value'] == 'api.acme.com')
    assert api['worst'] == 'high'


# ── F-K7: infra-level exposure (blast radius) ─────────────────────────────────

def test_infra_exposure_rolls_up_by_ip_asn_netblock():
    assets = _infra_assets() + [
        _asset('a-sub2', 'subdomain', 'cdn.acme.com', ip='1.2.3.4'),
        _asset('a-nb', 'netblock', '1.2.3.0/24'),
    ]
    findings = [
        _finding('f1', 'api.acme.com/graphql', 'critical'),  # api → 1.2.3.4
        _finding('f2', 'cdn.acme.com', 'high'),              # cdn → 1.2.3.4
    ]
    out = build_correlation(findings, assets)
    by = {(r['type'], r['node']): r for r in out['infra_exposure']}
    ip = by[('ip', '1.2.3.4')]
    assert ip['findings_count'] == 2          # both findings on one IP
    assert ip['host_count'] == 2              # across two hosts
    assert ip['worst'] == 'critical'
    # ASN + netblock aggregate the same two findings.
    assert by[('asn', 'AS13335')]['findings_count'] == 2
    assert by[('netblock', '1.2.3.0/24')]['findings_count'] == 2


def test_infra_exposure_sorted_worst_first():
    out = build_correlation([_finding('f', 'api.acme.com/graphql', 'critical')],
                            _infra_assets())
    assert out['infra_exposure'][0]['worst'] == 'critical'


# ── F-K2: report card ─────────────────────────────────────────────────────────

class _Project:
    def __init__(self, slug):
        self.slug = slug


def _seed_stores(project='p'):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    FindingsStore().sync(project, 's1', [{
        'category': 'graphql', 'title': 'GraphQL introspection',
        'severity': 'high', 'location': 'https://api.acme.com/graphql'}])
    AssetStore().sync(project, 's1', [
        Asset('subdomain', 'api.acme.com', attrs={'ip': '1.2.3.4'}),
        Asset('endpoint', 'api.acme.com/graphql')])


def test_build_correlation_populates_report():
    from core.collection_runner import CollectionRunner
    _seed_stores('p')
    report: dict = {}
    CollectionRunner()._build_correlation(report, _Project('p'))
    assert 'correlation' in report
    assert report['correlation']['summary']['correlated'] == 1
    assert report['correlation']['exposure'][0]['value'] == 'api.acme.com'


def test_build_correlation_skips_when_nothing():
    from core.collection_runner import CollectionRunner
    report: dict = {}
    CollectionRunner()._build_correlation(report, _Project('empty'))
    assert 'correlation' not in report   # no findings/assets → no card


def test_render_correlation_card_html():
    from core.collection_runner import CollectionRunner
    cdata = {'summary': {'correlated': 2, 'findings': 3, 'exposed_assets': 1},
             'exposure': [{'value': 'api.acme.com', 'label': 'api.acme.com',
                           'worst': 'critical', 'findings_count': 2}],
             'infra_exposure': [{'type': 'asn', 'node': 'AS13335',
                                 'worst': 'critical', 'findings_count': 2,
                                 'host_count': 1}]}
    out = CollectionRunner._render_correlation_card(cdata)
    assert 'api.acme.com' in out and 'critical' in out
    assert 'из 3' in out                 # correlated/total in the header
    assert 'blast radius' in out and 'AS13335' in out   # F-K7 infra line
