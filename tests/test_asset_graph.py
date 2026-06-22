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


def test_shared_infra_marks_cdn_clusters():
    # Hosts sharing a CDN edge IP (cloud=Cloudflare) are annotated cdn=True — an edge
    # artifact, not a real single point of exposure. A non-CDN shared IP is unmarked
    # (the marker is additive; nothing is dropped). Both clusters still appear.
    inv = [
        _asset('subdomain', 'a.x.com', ip='1.1.1.1'),
        _asset('subdomain', 'b.x.com', ip='1.1.1.1'),
        _asset('ip', '1.1.1.1', cloud='Cloudflare'),
        _asset('subdomain', 'c.y.com', ip='5.5.5.5'),
        _asset('subdomain', 'd.y.com', ip='5.5.5.5'),
        _asset('ip', '5.5.5.5', provider='Acme Hosting'),   # not a CDN
    ]
    by_node = {c['node']: c for c in ag.shared_infra(inv) if c['type'] == 'ip'}
    assert by_node['1.1.1.1'].get('cdn') is True
    assert by_node['1.1.1.1']['count'] == 2                  # not dropped
    assert 'cdn' not in by_node['5.5.5.5']                   # absent when not a CDN


def test_shared_infra_needs_two_members():
    # A single host on an IP is not a "shared" cluster.
    one = [_asset('subdomain', 'solo.x.com', ip='1.1.1.1'),
           _asset('ip', '1.1.1.1', asn='AS1')]
    assert ag.shared_infra(one) == []


def test_load_summary_shape_handles_empty():
    out = ag.build_asset_graph([])
    assert out == {'nodes': [], 'edges': []}
    assert ag.shared_infra([]) == []


# ── co-hosted related (infra-chain tail, Phase 2) ──────────────────────────────

def _related(shared_ip='1.2.3.4', hosts=('evil.com', 'other.org')):
    return {'shared_ip': shared_ip,
            'related': [{'host': h, 'shared_ip': shared_ip} for h in hosts]}


def test_co_hosted_adds_external_nodes_and_edges():
    g = ag.build_asset_graph(_inventory(), related=_related())
    # external nodes added with the `external` flag, type `related`.
    ext = [n for n in g['nodes'] if n.get('external')]
    assert {n['value'] for n in ext} == {'evil.com', 'other.org'}
    assert all(n['type'] == 'related' for n in ext)
    # co_hosted edge anchored on our owned IP node.
    co = _rels(g, 'co_hosted')
    assert ('ip:1.2.3.4', 'related:evil.com') in co
    assert ('ip:1.2.3.4', 'related:other.org') in co


def test_co_hosted_skipped_when_ip_not_owned():
    # shared IP is not an owned `ip` asset → no anchor, nothing added.
    g = ag.build_asset_graph(_inventory(), related=_related(shared_ip='8.8.8.8'))
    assert [n for n in g['nodes'] if n.get('external')] == []
    assert _rels(g, 'co_hosted') == set()


def test_co_hosted_dedups_and_skips_own_hosts():
    # a duplicate host and a host that collides with an owned node are dropped.
    rel = _related(hosts=('evil.com', 'evil.com', 'a.x.com'))
    g = ag.build_asset_graph(_inventory(), related=rel)
    ext = [n for n in g['nodes'] if n.get('external')]
    assert {n['value'] for n in ext} == {'evil.com'}   # dup + own-host filtered


def test_related_none_is_byte_for_byte_unchanged():
    base = ag.build_asset_graph(_inventory())
    same = ag.build_asset_graph(_inventory(), related=None)
    assert base == same
    assert len(base['nodes']) == 9
    assert not any(n.get('external') for n in base['nodes'])


def test_load_asset_graph_summary_counts_owned_only():
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    AssetStore().sync('x.com', 's1', [
        Asset('domain', 'x.com', attrs={'ip': '1.2.3.4'}),
        Asset('ip', '1.2.3.4', attrs={'asn': 'AS1'})])
    out = ag.load_asset_graph(
        'x.com', related={'shared_ip': '1.2.3.4',
                          'related': [{'host': 'evil.com'}]})
    s = out['summary']
    assert s['related'] == 1            # external co-hosted surfaced
    assert s['nodes'] == 2             # owned nodes only (external excluded)
    # the co_hosted edge is not counted in the owned `edges` total.
    co = [e for e in out['graph']['edges'] if e['rel'] == 'co_hosted']
    assert len(co) == 1
    assert s['edges'] == len(out['graph']['edges']) - 1


def test_load_asset_graph_related_none_has_zero_related():
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    AssetStore().sync('y.com', 's1', [Asset('domain', 'y.com')])
    out = ag.load_asset_graph('y.com')
    assert out['summary'].get('related', 0) == 0


def test_load_summary_counts_cdn_clusters():
    # The summary reports how many clusters are CDN-edge artefacts and the largest
    # *genuine* cluster, so the exposure metric can exclude the edge clusters.
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    AssetStore().sync('cdn.com', 's1', [
        Asset('subdomain', 'a.cdn.com', attrs={'ip': '1.1.1.1'}),
        Asset('subdomain', 'b.cdn.com', attrs={'ip': '1.1.1.1'}),
        Asset('subdomain', 'e.cdn.com', attrs={'ip': '1.1.1.1'}),
        Asset('ip', '1.1.1.1', attrs={'cloud': 'Cloudflare'}),       # CDN edge
        Asset('subdomain', 'c.cdn.com', attrs={'ip': '5.5.5.5'}),
        Asset('subdomain', 'd.cdn.com', attrs={'ip': '5.5.5.5'}),
        Asset('ip', '5.5.5.5', attrs={'provider': 'Acme Hosting'})]) # real
    s = ag.load_asset_graph('cdn.com')['summary']
    assert s['clusters'] == 2 and s['cdn_clusters'] == 1
    assert s['largest_cluster'] == 3            # overall (the 3-host CDN cluster)
    assert s['largest_real_cluster'] == 2       # largest non-CDN (5.5.5.5)


def test_shared_infra_ignores_external_related():
    # external co-hosted domains are not owned hosts → never in blast-radius clusters.
    g = ag.build_asset_graph(_inventory(), related=_related())
    # shared_infra reads the asset rows (owned), not the graph — unchanged.
    clusters = ag.shared_infra(_inventory())
    assert all('evil.com' not in c['members'] for c in clusters)
    # and the graph's external nodes carry no resolves/apex ownership edges.
    for n in (x for x in g['nodes'] if x.get('external')):
        assert not any(e['dst'] == n['id'] and e['rel'] != 'co_hosted'
                       for e in g['edges'])
