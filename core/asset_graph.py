"""core/asset_graph.py
Asset Correlation Engine — relationships *between assets* (Epic 5).

Where ``core.correlation`` is finding-centric (Finding → Asset → Infra), this module
is asset-centric: it derives the **topology of the inventory itself** — which assets
relate to which — and the *Exposure Intelligence* on top of it: which infrastructure
node concentrates many assets (a single point of exposure), independent of any
finding. The platform "understands relationships between assets", not just stores
them.

Edges (all derived from attributes the Asset Inventory already stores — no new data,
no new table, the derive-on-read pattern of F2/F5/correlation):

    domain ──apex──▶ subdomain        (subdomain within the apex)
    host   ──resolves──▶ ip           (host.attrs.ip)
    ip     ──announces──▶ asn         (ip.attrs.asn)
    netblock ──contains──▶ ip         (ip ∈ cidr — stdlib ipaddress)
    endpoint ──serves──▶ host         (host part of the endpoint path)

``shared_infra`` is the Exposure-Intelligence view: host assets grouped by a common
IP / ASN / netblock, so "12 subdomains resolve to one IP" surfaces as a blast-radius
cluster. Pure / stdlib / offline (I1/I2/I5); the CIDR match is reused from
``correlation`` so there is one implementation, not two.
"""

from typing import Dict, List, Optional

from core.cloud_classifier import classify_cloud, is_cdn_cloud
from core.correlation import _host, _netblock_for

# Edge relationship vocabulary (src → dst).
REL_APEX = 'apex'            # domain → subdomain
REL_RESOLVES = 'resolves'    # host → ip
REL_ANNOUNCES = 'announces'  # ip → asn
REL_CONTAINS = 'contains'    # netblock → ip
REL_SERVES = 'serves'        # endpoint → host
REL_CO_HOSTED = 'co_hosted'  # ip → related (external co-hosted domain)


def _within_apex(sub: str, apex: str) -> bool:
    """Whether ``sub`` is the apex itself or a host under it (``a.x.com`` ⊂ ``x.com``)."""
    sub = str(sub or '').strip().lower().rstrip('.')
    apex = str(apex or '').strip().lower().rstrip('.')
    return bool(apex) and (sub == apex or sub.endswith('.' + apex))


def _by_type(assets: List[Dict]) -> Dict[str, Dict[str, Dict]]:
    out: Dict[str, Dict[str, Dict]] = {}
    for a in assets:
        if isinstance(a, dict):
            out.setdefault(a.get('type'), {})[a.get('value')] = a
    return out


def build_asset_graph(assets: List[Dict], related: Optional[Dict] = None) -> Dict:
    """Asset-to-asset relationship graph for one project (pure).

    ``assets`` are ``AssetStore`` rows. Returns ``{nodes, edges}`` where a node is
    ``{id, type, value, label}`` and an edge is ``{src, dst, rel}`` (both endpoints
    are inventory assets — an edge is only drawn when both nodes exist).

    ``related`` (optional) is ``asn_intel.related_assets``' co-hosted view
    (``{shared_ip, related:[{host}], ...}``) — the last hop of the infra chain. Its
    hosts are *external* domains sharing our IP; they are added as ``external`` nodes
    of type ``related`` with a ``co_hosted`` edge from our owned IP node, **never** as
    owned inventory rows (a co-hosted neighbour is not our asset — the deliberate
    asn_intel policy). When ``related`` is ``None`` the output is byte-for-byte the
    owned-only graph."""
    assets = [a for a in (assets or []) if isinstance(a, dict)]
    bt = _by_type(assets)
    domains, subs = bt.get('domain', {}), bt.get('subdomain', {})
    ips, asns, netblocks = bt.get('ip', {}), bt.get('asn', {}), bt.get('netblock', {})
    endpoints = bt.get('endpoint', {})
    hosts = {**domains, **subs}

    nodes = [{'id': a.get('id'), 'type': a.get('type'), 'value': a.get('value'),
              'label': a.get('label') or a.get('value')} for a in assets]

    edges: List[Dict] = []
    seen = set()

    def add(src: Optional[str], dst: Optional[str], rel: str) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst, rel)
        if key not in seen:
            seen.add(key)
            edges.append({'src': src, 'dst': dst, 'rel': rel})

    for dval, dasset in domains.items():
        for sval, sasset in subs.items():
            if _within_apex(sval, dval):
                add(dasset.get('id'), sasset.get('id'), REL_APEX)
    for hasset in hosts.values():
        ip = (hasset.get('attrs') or {}).get('ip')
        if ip in ips:
            add(hasset.get('id'), ips[ip].get('id'), REL_RESOLVES)
    for ip, ipasset in ips.items():
        asn = (ipasset.get('attrs') or {}).get('asn')
        if asn in asns:
            add(ipasset.get('id'), asns[asn].get('id'), REL_ANNOUNCES)
        nb = _netblock_for(ip, netblocks)
        if nb in netblocks:
            add(netblocks[nb].get('id'), ipasset.get('id'), REL_CONTAINS)
    for epval, epasset in endpoints.items():
        h = _host(epval)
        if h in hosts:
            add(epasset.get('id'), hosts[h].get('id'), REL_SERVES)

    _add_co_hosted(related, ips, nodes, add)

    return {'nodes': nodes, 'edges': edges}


def _add_co_hosted(related: Optional[Dict], ips: Dict[str, Dict],
                   nodes: List[Dict], add) -> None:
    """Append external co-hosted domains as ``related`` nodes anchored on our owned IP.

    Only attaches when the shared IP is itself an owned ``ip`` asset (the anchor must
    exist — same "both endpoints exist" invariant). De-duplicates hosts and skips any
    that collide with an existing node value (our own hosts are already filtered out
    by ``related_assets``)."""
    if not isinstance(related, dict):
        return
    shared_ip = str(related.get('shared_ip') or '').strip()
    ipasset = ips.get(shared_ip)
    if not shared_ip or not ipasset:
        return
    existing = {n.get('value') for n in nodes}
    seen = set()
    for entry in related.get('related') or []:
        host = str((entry or {}).get('host') or '').strip().lower().rstrip('.')
        if not host or host in seen or host in existing:
            continue
        seen.add(host)
        nid = f'related:{host}'
        nodes.append({'id': nid, 'type': 'related', 'value': host,
                      'label': host, 'external': True})
        add(ipasset.get('id'), nid, REL_CO_HOSTED)


def asset_neighbors(graph: Dict, asset_id: str) -> List[Dict]:
    """Assets directly related to ``asset_id`` — ``[{id, type, value, label, rel}]``.

    Both edge directions count (a host's ip and an ip's hosts are both neighbours);
    de-duplicated by neighbour id (first relationship wins)."""
    by_id = {n.get('id'): n for n in (graph or {}).get('nodes', [])}
    out: List[Dict] = []
    seen = set()
    for e in (graph or {}).get('edges', []):
        other = (e.get('dst') if e.get('src') == asset_id
                 else e.get('src') if e.get('dst') == asset_id else None)
        if other and other not in seen and other in by_id:
            seen.add(other)
            out.append({**by_id[other], 'rel': e.get('rel')})
    return out


def shared_infra(assets: List[Dict], *, min_members: int = 2) -> List[Dict]:
    """Exposure Intelligence: host assets sharing a common ip / asn / netblock.

    A cluster of ``min_members``+ hosts on one infrastructure node is a single point
    of exposure (compromise the node → every member is affected) — blast radius at
    the *asset* level, regardless of findings. Returns
    ``[{type, node, members:[host values], count[, cdn]}]``, largest cluster first;
    ``cdn=True`` marks a cluster whose shared node is a pure CDN edge (Cloudflare/
    Fastly/Akamai) — an edge artifact, not a real single point of exposure — so
    consumers can de-emphasise it without it being silently dropped. The ASN of a
    host is resolved via its IP's ``ip`` asset (subdomains carry ``ip`` but not
    ``asn`` directly)."""
    assets = [a for a in (assets or []) if isinstance(a, dict)]
    bt = _by_type(assets)
    hosts = {**bt.get('domain', {}), **bt.get('subdomain', {})}
    ips, netblocks, asns = bt.get('ip', {}), bt.get('netblock', {}), bt.get('asn', {})

    def _asn_of(ip: str) -> Optional[str]:
        a = ips.get(ip)
        return (a.get('attrs') or {}).get('asn') if a else None

    def _node_cloud(ntype: str, node: str) -> str:
        """The cloud attributed to a cluster's infra node — the already-derived
        ``attrs.cloud`` first, else classified from its provider / ASN."""
        asset = {'ip': ips, 'asn': asns, 'netblock': netblocks}.get(ntype, {}).get(node)
        attrs = (asset or {}).get('attrs') or {}
        if attrs.get('cloud'):
            return str(attrs['cloud'])
        return classify_cloud(
            provider=str(attrs.get('provider') or ''),
            asn_name=str(attrs.get('name') or attrs.get('org') or ''),
            asn=node if ntype == 'asn' else '',
        ).get('cloud', '')

    clusters: Dict[tuple, set] = {}

    def put(ntype: str, node, host: str) -> None:
        if node:
            clusters.setdefault((ntype, str(node)), set()).add(host)

    for hval, hasset in hosts.items():
        attrs = hasset.get('attrs') or {}
        ip = attrs.get('ip')
        if ip:
            put('ip', ip, hval)
            put('netblock', _netblock_for(ip, netblocks), hval)
            put('asn', _asn_of(ip) or attrs.get('asn'), hval)
        elif attrs.get('asn'):
            put('asn', attrs['asn'], hval)

    rows: List[Dict] = []
    for (ntype, node), members in clusters.items():
        if len(members) < min_members:
            continue
        row = {'type': ntype, 'node': node,
               'members': sorted(members), 'count': len(members)}
        # Annotate (never exclude) a cluster whose shared node is a pure CDN edge:
        # many hosts on one Cloudflare/Fastly/Akamai IP is an edge artifact, not a
        # real single point of exposure. Consumers can de-emphasise these.
        if is_cdn_cloud(_node_cloud(ntype, str(node))):
            row['cdn'] = True
        rows.append(row)
    rows.sort(key=lambda r: (-r['count'], r['type'], r['node']))
    return rows


def load_asset_graph(project: str, related: Optional[Dict] = None) -> Dict:
    """Build a project's asset graph + exposure clusters (thin store reader).

    Reads the project's assets from the Asset Inventory and delegates to the pure
    builders. Offline, read-only; guarded — a store failure degrades to an empty
    graph rather than crashing the caller (mirrors ``correlation.load_correlation``).

    ``related`` (optional) is ``asn_intel``'s co-hosted view; when supplied its
    external domains are surfaced as ``related`` nodes (see :func:`build_asset_graph`).
    The summary keeps ``nodes``/``edges`` measuring the *owned* topology (external
    nodes / co-hosted edges are reported separately as ``related``) so existing
    metrics are unchanged when ``related`` is ``None``."""
    try:
        from core.asset_store import AssetStore
        assets = AssetStore().list_assets(project=project)
        graph = build_asset_graph(assets, related=related)
        clusters = shared_infra(assets)
        owned_nodes = [n for n in graph['nodes'] if not n.get('external')]
        owned_edges = [e for e in graph['edges'] if e.get('rel') != REL_CO_HOSTED]
        related_count = len(graph['nodes']) - len(owned_nodes)
        return {
            'graph': graph,
            'shared_infra': clusters,
            'summary': {
                'nodes': len(owned_nodes),
                'edges': len(owned_edges),
                'clusters': len(clusters),
                'largest_cluster': clusters[0]['count'] if clusters else 0,
                'related': related_count,
            },
        }
    except Exception as e:  # noqa: BLE001 — surface as data, never crash a caller
        return {'graph': {'nodes': [], 'edges': []}, 'shared_infra': [],
                'summary': {}, 'error': str(e)}
