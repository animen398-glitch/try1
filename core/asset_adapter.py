"""core/asset_adapter.py
Derive deduplicated Asset DTOs from a scan report (Asset Inventory foundation).

Assets are the *head* of the platform chain (Assets → Events → Findings → Risk →
Timeline → …). This adapter is the asset analogue of ``findings_adapter``: a pure,
offline deriver that turns the data already produced by the scan phases
(recon / subdomains / asn_intel / katana / openapi …) into a flat list of
``Asset`` DTOs with a **stable identity**, so the same asset deduplicates and
keeps that identity across scans. The scanners are NOT touched — we read the
report they already build (architectural invariants I1/I3/I5).

Identity mirrors the proven finding fingerprint design:

    asset_id = sha1( type ␟ normalized_value )

reusing ``finding_fingerprint.normalize_location`` for endpoints (drops query/
fragment/scheme → ``host/path``, so http/https/query variants are one asset) and
``finding_fingerprint.scoped_id`` for the project-scoped storage key. Version/provider/etc. are *attributes*, not identity — a version
bump is a change of one asset, not a new one.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlsplit

from core.finding_fingerprint import normalize_location
from core.finding_fingerprint import scoped_id  # noqa: F401 (re-exported for store)

# Asset type vocabulary (the ``type`` component of the identity). Each type maps
# to the scan phase that produces it — used by the sync layer to gate "gone"
# detection to types whose source phase actually ran (a skipped phase ≠ gone).
ASSET_TYPES = ('domain', 'subdomain', 'ip', 'asn', 'netblock', 'endpoint',
               'technology')

# type → producing phase(s). 'endpoint' comes from either katana or openapi.
ASSET_SOURCE_PHASES = {
    'domain': ('recon',), 'ip': ('recon',), 'asn': ('recon',),
    'technology': ('recon',), 'subdomain': ('subdomains',),
    'netblock': ('asn_intel',), 'endpoint': ('katana', 'openapi'),
}

_SEP = '\x1f'   # ASCII Unit Separator — never in a normalized value (collision-safe)


def _normalize_value(atype: str, value: str) -> str:
    """Canonical, identity-bearing form of an asset value for its type."""
    v = str(value or '').strip()
    if not v:
        return ''
    if atype == 'endpoint':
        return normalize_location(v)
    if atype in ('domain', 'subdomain', 'ip', 'asn', 'technology'):
        return v.rstrip('.').lower()
    return v.lower()   # netblock / any other


def asset_fingerprint(atype: str, value: str) -> str:
    """Stable SHA-1 identity for an asset from ``(type, normalized value)``."""
    parts = (str(atype).strip().lower(), _normalize_value(atype, value))
    return hashlib.sha1(_SEP.join(parts).encode('utf-8')).hexdigest()


@dataclass
class Asset:
    """A discovered asset DTO. ``attrs`` carries non-identity context (version,
    provider, source phase …) that may change between scans."""
    type: str
    value: str
    label: str = ''
    attrs: Dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # ``value`` is the identity-bearing normalized form; the original display
        # string is preserved in ``label`` (so http/https/case variants are one
        # asset while the UI still shows what was observed).
        original = str(self.value or '')
        if not self.label:
            self.label = original
        self.value = _normalize_value(self.type, original)

    @property
    def id(self) -> str:
        return asset_fingerprint(self.type, self.value)

    def to_store(self) -> Dict:
        return {'id': self.id, 'type': self.type, 'value': self.value,
                'label': self.label or self.value, 'attrs': self.attrs}


def _phase(report: Dict, name: str) -> Dict:
    p = report.get('phases', {}).get(name, {})
    data = p.get('data', {}) if isinstance(p, dict) else {}
    return data if isinstance(data, dict) else {}


def _host_of(url: str) -> str:
    if not url:
        return ''
    if '://' not in url:
        url = 'http://' + url
    return urlsplit(url).netloc.lower()


def _present(**kwargs) -> Dict:
    """Keep only the truthy/meaningful values — so enriched attrs carry no
    ``None``/empty noise (cleaner detail panel, smaller stored JSON)."""
    return {k: v for k, v in kwargs.items() if v not in (None, '', [], {})}


def _is_concrete_host(host: str, apex: str) -> bool:
    """A TLS/CT name worth promoting to its own subdomain asset: a concrete name
    *within the target apex*. Excludes wildcards (``*.x``), the apex itself (that
    is the ``domain`` asset, not a subdomain) and unrelated names a multi-SAN
    certificate may carry (only ``*.apex`` hosts are this project's subdomains)."""
    h = str(host or '').strip().lower().rstrip('.')
    if not h or h.startswith('*.') or h == apex or not apex:
        return False
    return h.endswith('.' + apex)


def _split_sans(sans) -> List[str]:
    """Certificate SANs come comma-joined from ``cert_info`` — split into a list
    of distinct hostnames (``DNS:`` prefixes stripped, lowercased, de-duped)."""
    items = sans if isinstance(sans, (list, tuple)) else str(sans or '').split(',')
    out: List[str] = []
    seen = set()
    for s in items:
        h = str(s or '').strip().lower().removeprefix('dns:').strip().rstrip('.')
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def derive_assets(report: Dict) -> List[Asset]:
    """Extract every asset from a scan ``report``, deduplicated by identity.

    Tolerant of missing phases — each extractor is guarded, so a partial scan
    yields fewer assets rather than failing. Returns ``Asset`` DTOs in stable
    order, one per unique ``(type, normalized value)``.
    """
    recon = _phase(report, 'recon')
    infra = recon.get('infrastructure') if isinstance(
        recon.get('infrastructure'), dict) else {}
    out: List[Asset] = []

    # domain (the target host). Carry the apex IP/ASN so domain-level findings
    # resolve the full infra chain (ip → asn → netblock), same as subdomains do
    # via their own ``attrs.ip`` — correlation reads these (F-K5). Enriched with
    # the served TLS certificate facts (issuer / expiry / subject / SANs) and the
    # hosting provider/location — all already in the report (F-A1).
    cert = _phase(report, 'certificate')
    domain = (report.get('domain') or _host_of(report.get('url', '')))
    if domain:
        attrs = {'source': 'recon',
                 'ip': recon.get('ip') or infra.get('ip'),
                 'asn': infra.get('asn')}
        attrs.update(_present(
            provider=infra.get('provider'), location=infra.get('location'),
            tls_issuer=cert.get('issuer'), tls_subject=cert.get('subject'),
            tls_not_after=cert.get('not_after'),
            tls_sans=_split_sans(cert.get('sans'))))
        out.append(Asset('domain', domain, attrs=attrs))

    # subdomains (opt-in phase). The active probe already resolved CNAME / hosting
    # service / takeover / HTTP status / Server header — surface them as context
    # (non-identity), so the inventory shows *what* each subdomain is (F-A1).
    sub = _phase(report, 'subdomains')
    results = sub.get('results') if isinstance(sub.get('results'), list) else []
    for e in results:
        if isinstance(e, dict) and e.get('subdomain'):
            attrs = {'source': 'subdomains', 'ip': e.get('ip')}
            attrs.update(_present(
                cname=e.get('cname'), service=e.get('service'),
                takeover=e.get('takeover') or None, server=e.get('server'),
                http_status=e.get('http_status'), title=e.get('title'),
                status=e.get('status')))
            out.append(Asset('subdomain', e['subdomain'], attrs=attrs))

    # Subdomains observed in TLS material but not actively probed: the served
    # certificate's SANs and the CT-log history (crt.sh). These are real, owned
    # names — promote them to first-class subdomain assets (previously they only
    # rode along in ``domain.attrs.tls_sans``). Their distinct ``source``
    # ('certificate' / 'ct') lets the store gate GONE per-source, so a scan that
    # skipped the cert/CT phase never flaps them GONE just because the active
    # subdomain phase ran (F-A1 tail). Probe results above win the identity (first
    # occurrence keeps its richer attrs); these only add names not already seen.
    apex = (domain or '').lower().rstrip('.')
    for host in _split_sans(cert.get('sans')):
        if _is_concrete_host(host, apex):
            out.append(Asset('subdomain', host, attrs={'source': 'certificate'}))
    ct = _phase(report, 'ct')
    for host in ct.get('names') or []:
        if _is_concrete_host(host, apex):
            out.append(Asset('subdomain', str(host).strip().lower().rstrip('.'),
                             attrs={'source': 'ct'}))

    # ip (recon + infrastructure chain) — carry the provider/location too.
    for ip in (recon.get('ip'), infra.get('ip')):
        if ip:
            attrs = {'source': 'recon', 'asn': infra.get('asn')}
            attrs.update(_present(provider=infra.get('provider'),
                                  location=infra.get('location')))
            out.append(Asset('ip', str(ip), attrs=attrs))

    # asn
    if infra.get('asn'):
        out.append(Asset('asn', infra['asn'], label=f"{infra['asn']} "
                         f"{infra.get('asn_name', '')}".strip(),
                         attrs={'source': 'recon',
                                'name': infra.get('asn_name'),
                                'provider': infra.get('provider'),
                                **_present(org=infra.get('org'),
                                           location=infra.get('location'))}))

    # netblocks (active ASN intel, opt-in): the IP's CIDR + all ASN prefixes
    asn_intel = _phase(report, 'asn_intel')
    if asn_intel.get('cidr'):
        out.append(Asset('netblock', asn_intel['cidr'],
                         attrs={'source': 'asn_intel', 'kind': 'cidr'}))
    for prefix in asn_intel.get('prefixes') or []:
        if prefix:
            out.append(Asset('netblock', str(prefix),
                             attrs={'source': 'asn_intel', 'kind': 'prefix'}))

    # technologies (recon fingerprint + CMS); identity = name, version = attr
    for t in recon.get('technologies') or []:
        if isinstance(t, dict) and t.get('name'):
            out.append(Asset('technology', t['name'],
                             attrs={'source': 'recon', 'version': t.get('version'),
                                    'category': t.get('category')}))
    for cms in recon.get('cms') or []:
        if cms:
            out.append(Asset('technology', str(cms), attrs={'source': 'recon'}))

    # endpoints (opt-in external crawl + OpenAPI map)
    katana = _phase(report, 'katana')
    for ep in katana.get('endpoints') or []:
        if ep:
            out.append(Asset('endpoint', str(ep), attrs={'source': 'katana'}))
    openapi = _phase(report, 'openapi')
    for ep in openapi.get('endpoints') or []:
        if isinstance(ep, dict) and ep.get('path'):
            out.append(Asset('endpoint', ep['path'],
                             attrs={'source': 'openapi',
                                    'method': ep.get('method')}))

    return _dedup(out)


def _dedup(assets: List[Asset]) -> List[Asset]:
    """One asset per identity; first occurrence wins (keeps its attrs)."""
    seen, unique = set(), []
    for a in assets:
        if not a.value or not _normalize_value(a.type, a.value):
            continue
        if a.id in seen:
            continue
        seen.add(a.id)
        unique.append(a)
    return unique
