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

    # domain (the target host)
    domain = (report.get('domain') or _host_of(report.get('url', '')))
    if domain:
        out.append(Asset('domain', domain, attrs={'source': 'recon'}))

    # subdomains (opt-in phase)
    sub = _phase(report, 'subdomains')
    results = sub.get('results') if isinstance(sub.get('results'), list) else []
    for e in results:
        if isinstance(e, dict) and e.get('subdomain'):
            out.append(Asset('subdomain', e['subdomain'],
                             attrs={'source': 'subdomains',
                                    'ip': e.get('ip')}))

    # ip (recon + infrastructure chain)
    for ip in (recon.get('ip'), infra.get('ip')):
        if ip:
            out.append(Asset('ip', str(ip), attrs={'source': 'recon',
                                                   'asn': infra.get('asn')}))

    # asn
    if infra.get('asn'):
        out.append(Asset('asn', infra['asn'], label=f"{infra['asn']} "
                         f"{infra.get('asn_name', '')}".strip(),
                         attrs={'source': 'recon',
                                'name': infra.get('asn_name'),
                                'provider': infra.get('provider')}))

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
