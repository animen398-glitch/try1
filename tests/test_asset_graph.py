"""Asset Correlation Engine (core/asset_graph.py, EPIC 5) — pure, offline.

Operates on AssetStore-shaped rows: relationship edges (apex/resolves/announces/
contains/serves), neighbours, and the shared-infrastructure exposure clusters.
"""

from core import asset_graph as ag


def _asset(atype, value, *, id=None, label=None, **attrs):
    return {'id': id or f'{atype}:{value}', 'type': atype, 'value': value,
            'label': label or value, 'attrs': attrs}


def _inventory():
    # apex x.com with two subdomains resolving to one shared IP, plus a second IP;
    # the IP sits in an ASN and a netblock; an endpoint serves a subdomain.
    return [
        _asset('domain', 'x.com', ip='1.2.3.4', asn='AS13335'),
        _asset('subdomain', 'a.x.com', ip='1.2.3.4'),
        _asset('subdomain', 'b.x.com', ip='1.2.3.4'),
        _asset('subdomain', 'c.x.com', ip='9.9.9.9'),
        _asset('ip', '1.2.3.4', asn='AS13335'),
        _asset('ip', '9.9.9.9', asn='AS13335'),
        _asset('asn', 'AS13335', name='Cloudflare'),
        _asset('netblock', '1.2.3.0/24'),
        _asset('endpoint', 'a.x.com/login'),
    ]


def _rels(graph, rel):
    return {(e['src'], e['dst']) for e in graph['edges'] if e['rel'] == rel}


def test_graph_edges_cover_each_relationship():
    g = ag.build_asset_graph(_inventory())
    assert len(g['nodes']) == 9
    # apex: domain → each subdomain
    apex = _rels(g, 'apex')
    assert ('domain:x.com', 'subdomain:a.x.com') in apex
    assert ('domain:x.com', 'subdomain:c.x.com') in apex
    # resolves: host → ip
    assert ('subdomain:a.x.com', 'ip:1.2.3.4') in _rels(g, 'resolves')
    assert ('domain:x.com', 'ip:1.2.3.4') in _rels(g, 'resolves')
    # announces: ip → asn
    assert ('ip:1.2.3.4', 'asn:AS13335') in _rels(g, 'announces')
    # contains: netblock ∋ ip (CIDR)
    assert ('netblock:1.2.3.0/24', 'ip:1.2.3.4') in _rels(g, 'contains')
    assert ('netblock:1.2.3.0/24', 'ip:9.9.9.9') not in _rels(g, 'contains')
    # serves: endpoint → host
    assert ('endpoint:a.x.com/login', 'subdomain:a.x.com') in _rels(g, 'serves')


def test_no_edge_when_target_asset_absent():
    # subdomain resolves to an IP that is not in the inventory → no resolves edge.
    assets = [_asset('subdomain', 'a.x.com', ip='5.5.5.5')]
    assert ag.build_asset_graph(assets)['edges'] == []


def test_neighbors_both_directions():
    g = ag.build_asset_graph(_inventory())
    nbrs = {n['value'] for n in ag.asset_neighbors(g, 'ip:1.2.3.4')}
    # the IP's neighbours: the hosts resolving to it, its ASN, its netblock
    assert {'x.com', 'a.x.com', 'b.x.com', 'AS13335', '1.2.3.0/24'} <= nbrs


def test_shared_infra_clusters_blast_radius():
    clusters = ag.shared_infra(_inventory())
    ip_cluster = next(c for c in clusters if c['type'] == 'ip')
    assert ip_cluster['node'] == '1.2.3.4' and ip_cluster['count'] == 3
    assert ip_cluster['members'] == ['a.x.com', 'b.x.com', 'x.com']
    # all four hosts share the ASN (via their IPs)
    asn_cluster = next(c for c in clusters if c['type'] == 'asn')
    assert asn_cluster['count'] == 4
    # largest first
    assert clusters[0]['count'] >= clusters[-1]['count']


def test_shared_infra_needs_two_members():
    # A single host on an IP is not a "shared" cluster.
    one = [_asset('subdomain', 'solo.x.com', ip='1.1.1.1'),
           _asset('ip', '1.1.1.1', asn='AS1')]
    assert ag.shared_infra(one) == []


def test_load_summary_shape_handles_empty():
    out = ag.build_asset_graph([])
    assert out == {'nodes': [], 'edges': []}
    assert ag.shared_infra([]) == []
