"""core/correlation.py
Cross-entity correlation — link findings ↔ assets ↔ infrastructure (Epic F-K1).

The platform already *collects* findings (F1) and assets (Asset Inventory) well,
but they live in separate project-keyed stores with no link between them. This
module closes that gap — the "manage data, not collect more" direction — by
**deriving** the links from keys that already exist, with no new table and no
schema change (the derive-on-read pattern of F2/F5/Company):

    Finding ─(location)→ Endpoint ─(host)→ Subdomain/Domain ─(attrs.ip)→ IP
            ─(attrs.asn)→ ASN ─→ Netblock

The join keys (verified in the stores):
  * ``Finding.evidence.location`` is ``host/path`` (``finding_fingerprint.
    normalize_location``) — identical to an ``endpoint`` asset's ``value``.
  * the host part of that location matches a ``subdomain``/``domain`` asset value.
  * a ``subdomain`` asset carries ``attrs.ip``; an ``ip`` asset carries
    ``attrs.asn`` — so the infra chain resolves from attributes already stored.

Pure / stdlib-only and offline (architectural invariants I1/I2/I5): the aggregator
is a pure function over already-loaded store rows; ``load_correlation`` is the thin
store reader. Stores are global (project-keyed), so no projects ``base`` is needed.
"""

import ipaddress
from typing import Dict, List, Optional

# Canonical severity scale (worst → least). Mirrors findings_adapter's lowercase
# scale; used to pick a "worst" severity and to bucket counts.
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'info')
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _sev(value) -> str:
    s = str(value or '').strip().lower()
    return s if s in _SEVERITY_RANK else 'info'


def _host(location: str) -> str:
    """Host part of a normalized ``host/path`` finding location (or '')."""
    loc = str(location or '').strip().lower()
    return loc.split('/', 1)[0] if loc else ''


def _netblock_for(ip: str, netblocks) -> Optional[str]:
    """The most specific netblock (CIDR) that contains ``ip``, or None (F-K6).

    Offline, stdlib ``ipaddress``: tests each netblock asset's value as a network
    and returns the longest-prefix (tightest) match. Bad IPs/CIDRs are skipped."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    best, best_len = None, -1
    for cidr in netblocks:
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        if addr in net and net.prefixlen > best_len:
            best, best_len = cidr, net.prefixlen
    return best


def _worst(severities) -> Optional[str]:
    """The worst (highest-ranked) severity in an iterable, or None if empty."""
    best = None
    for s in severities:
        s = _sev(s)
        if best is None or _SEVERITY_RANK[s] < _SEVERITY_RANK[best]:
            best = s
    return best


def _empty_counts() -> Dict[str, int]:
    return {s: 0 for s in SEVERITY_ORDER}


def build_correlation(findings: List[Dict], assets: List[Dict]) -> Dict:
    """Correlate ``findings`` with ``assets`` for one project (pure, F-K1).

    Both lists are store rows (``FindingsStore`` / ``AssetStore``). Returns:

      * ``finding_chains`` — ``finding_id → {host, endpoint, ip, asn, asn_name,
        provider, netblock}`` resolved infra chain for the finding's location;
      * ``asset_findings`` — ``asset_id → {findings, severity_counts, worst}`` for
        findings *directly* attached to that asset (endpoint or host match);
      * ``exposure`` — host assets (subdomain/domain) with their findings rolled
        up *including the endpoints under them*, worst-severity first (the
        "exposure by asset" view);
      * ``summary`` — totals + how many findings correlated to an asset.
    """
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    assets = [a for a in (assets or []) if isinstance(a, dict)]

    by_type: Dict[str, Dict[str, Dict]] = {}
    for a in assets:
        by_type.setdefault(a.get('type'), {})[a.get('value')] = a
    endpoints = by_type.get('endpoint', {})
    hosts = {**by_type.get('domain', {}), **by_type.get('subdomain', {})}
    ips = by_type.get('ip', {})
    asns = by_type.get('asn', {})
    netblocks = by_type.get('netblock', {})

    def _chain_for_host(host: str) -> Dict:
        chain: Dict = {}
        host_asset = hosts.get(host)
        if not host_asset:
            return chain
        chain['host'] = host_asset.get('label') or host
        ip = (host_asset.get('attrs') or {}).get('ip')
        if ip:
            chain['ip'] = ip
            netblock = _netblock_for(ip, netblocks)   # F-K6: ip ∈ cidr
            if netblock:
                chain['netblock'] = netblock
            ip_asset = ips.get(ip)
            asn = (ip_asset.get('attrs') or {}).get('asn') if ip_asset else None
            if asn:
                chain['asn'] = asn
                asn_asset = asns.get(asn)
                if asn_asset:
                    attrs = asn_asset.get('attrs') or {}
                    if attrs.get('name'):
                        chain['asn_name'] = attrs['name']
                    if attrs.get('provider'):
                        chain['provider'] = attrs['provider']
        return chain

    finding_chains: Dict[str, Dict] = {}
    asset_findings: Dict[str, Dict] = {}
    correlated = 0

    def _attach(asset_id: str, finding: Dict) -> None:
        bucket = asset_findings.get(asset_id)
        if bucket is None:
            bucket = asset_findings[asset_id] = {
                'findings': [], 'severity_counts': _empty_counts()}
        bucket['findings'].append(finding)
        bucket['severity_counts'][_sev(finding.get('severity'))] += 1

    for f in findings:
        loc = str((f.get('evidence') or {}).get('location') or '')
        host = _host(loc)
        chain = _chain_for_host(host)
        ep_asset = endpoints.get(loc)
        if ep_asset is not None:
            chain['endpoint'] = ep_asset.get('label') or loc
            _attach(ep_asset['id'], f)
            correlated += 1
        elif host and host in hosts:
            _attach(hosts[host]['id'], f)
            correlated += 1
        finding_chains[f.get('id')] = chain

    for bucket in asset_findings.values():
        bucket['worst'] = _worst(
            x.get('severity') for x in bucket['findings'])

    exposure = _build_exposure(hosts, endpoints, asset_findings, findings)

    totals = _empty_counts()
    for f in findings:
        totals[_sev(f.get('severity'))] += 1
    summary = {
        'findings': len(findings),
        'correlated': correlated,
        'uncorrelated': len(findings) - correlated,
        'severity_counts': totals,
        'exposed_assets': len(exposure),
    }
    return {'finding_chains': finding_chains, 'asset_findings': asset_findings,
            'exposure': exposure, 'summary': summary}


def _build_exposure(hosts: Dict, endpoints: Dict, asset_findings: Dict,
                    findings: List[Dict]) -> List[Dict]:
    """Host assets with findings rolled up *including their endpoints*.

    A finding hangs off the most specific asset (endpoint when matched), so a
    host's exposure must also fold in the findings of every endpoint whose host
    is this host. De-dups by finding id so a finding counted on an endpoint is
    not double-counted on its host."""
    # endpoint asset id → its host (for rolling endpoint findings up to the host)
    ep_host = {a['id']: _host(value) for value, a in endpoints.items()}

    rows: List[Dict] = []
    for value, host_asset in hosts.items():
        seen = set()
        counts = _empty_counts()
        total = 0
        # direct host findings
        for src_id, bucket in (
                [(host_asset['id'], asset_findings.get(host_asset['id']))]
                + [(eid, asset_findings.get(eid))
                   for eid, h in ep_host.items() if h == value]):
            if not bucket:
                continue
            for f in bucket['findings']:
                fid = f.get('id')
                if fid in seen:
                    continue
                seen.add(fid)
                counts[_sev(f.get('severity'))] += 1
                total += 1
        if total == 0:
            continue
        rows.append({
            'asset_id': host_asset['id'],
            'type': host_asset.get('type'),
            'value': value,
            'label': host_asset.get('label') or value,
            'findings_count': total,
            'severity_counts': counts,
            'worst': _worst(s for s, n in counts.items() for _ in range(n)),
        })
    # Worst severity first, then most findings.
    rows.sort(key=lambda r: (_SEVERITY_RANK.get(r['worst'], 99),
                             -r['findings_count']))
    return rows


def load_correlation(project: str) -> Dict:
    """Correlate one project's active findings with its assets (thin reader).

    Reads the risk-bearing (active, un-triaged-away) findings from the F1 store
    and the project's assets from the Asset Inventory, then delegates to the pure
    aggregator. Offline, read-only; run it off the GUI thread (I4). Guarded — a
    store failure degrades to an empty correlation rather than crashing the UI.
    """
    try:
        from core.asset_store import AssetStore
        from core.findings_store import FindingsStore
        findings = FindingsStore().active_findings(project)
        assets = AssetStore().list_assets(project=project)
        return build_correlation(findings, assets)
    except Exception as e:  # noqa: BLE001 — surface as data, never crash a caller
        return {'finding_chains': {}, 'asset_findings': {}, 'exposure': [],
                'summary': {}, 'error': str(e)}
