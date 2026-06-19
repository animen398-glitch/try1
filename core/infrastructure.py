"""core/infrastructure.py
ASN & infrastructure intelligence (Amass-style chain), stdlib only.

Recon already pulls the ASN / organisation / ISP fields from ip-api
(``fields=…,isp,org,as``); this module *surfaces* that data as a
Domain → ASN → IP → Provider chain instead of leaving it buried in the GeoIP
blob. No new network call and no dependency (architectural invariants I1/I5):
a single ``build_infrastructure(recon)`` returns a plain dict, and
``render_html`` emits a self-contained offline fragment for the report (I2).
"""

import html
import re
from typing import Dict, List, Optional

# ip-api 'as' field looks like "AS13335 Cloudflare, Inc." → number + name.
_AS_RE = re.compile(r'(AS\d+)\s*(.*)', re.IGNORECASE)


def parse_as_field(as_field: str):
    """Split an ip-api ``as`` string into ``(asn, asn_name)``.

    ``"AS13335 Cloudflare, Inc."`` → ``("AS13335", "Cloudflare, Inc.")``.
    Returns ``(None, "")`` when no ASN number is present.
    """
    m = _AS_RE.search(as_field or '')
    if not m:
        return None, ''
    return m.group(1).upper(), m.group(2).strip()


def build_infrastructure(recon: Dict) -> Dict:
    """Derive the infrastructure chain from a recon result dict.

    Reads ``domain``, ``ip`` and the GeoIP ``geo`` (as/org/isp/country/city) and
    returns ``{domain, ip, asn, asn_name, org, isp, provider, cloud, region,
    country, location, chain}`` where ``chain`` is the ordered, non-empty
    Domain → ASN → IP → Provider → Cloud → Region hops.

    ``cloud`` is the normalised hosting provider (AWS / Cloudflare / …) derived
    purely from the provider/ASN string by :mod:`core.cloud_classifier` — no new
    network call. ``region``/``country`` are the GeoIP region surfaced as structured
    fields (previously only joined into the ``location`` string). True cloud regions
    (``us-east-1``) are not offline-derivable from GeoIP and are deliberately not
    invented here.
    """
    geo = recon.get('geo') or {}
    domain = recon.get('domain') or ''
    ip = recon.get('ip')
    asn, asn_name = parse_as_field(geo.get('as', ''))
    org = (geo.get('org') or '').strip()
    isp = (geo.get('isp') or '').strip()
    provider = org or asn_name or isp

    region = (geo.get('regionName') or '').strip()
    country = (geo.get('country') or '').strip()
    location = ', '.join(
        p for p in (geo.get('city'), region, country) if p
    )

    # Normalise the hosting cloud from the vendor/ASN string (offline, no guess).
    # Tech / CNAME signals are added at the asset level (asset_adapter), where the
    # full technology list and per-subdomain CNAMEs are available.
    from core.cloud_classifier import classify_cloud
    cinfo = classify_cloud(provider=provider, asn_name=asn_name, asn=asn or '')
    cloud = cinfo.get('cloud', '')

    chain: List[Dict] = []
    if domain:
        chain.append({'role': 'Domain', 'value': domain})
    if asn:
        chain.append({'role': 'ASN', 'value': f'{asn} {asn_name}'.strip()})
    if ip:
        chain.append({'role': 'IP', 'value': ip})
    if provider:
        chain.append({'role': 'Provider', 'value': provider})
    if cloud:
        chain.append({'role': 'Cloud', 'value': cloud})
    region_value = ', '.join(p for p in (region, country) if p)
    if region_value:
        chain.append({'role': 'Region', 'value': region_value})

    return {
        'domain': domain,
        'ip': ip,
        'asn': asn,
        'asn_name': asn_name,
        'org': org,
        'isp': isp,
        'provider': provider,
        'cloud': cloud,
        'region': region,
        'country': country,
        'location': location,
        'chain': chain,
    }


def render_html(infra: Optional[Dict]) -> str:
    """Render the infrastructure chain as an offline inline-CSS fragment."""
    e = html.escape
    infra = infra or {}
    chain = infra.get('chain') or []
    if not chain:
        return ('<p style="font-size:13px;color:#999;">'
                'Недостаточно данных об инфраструктуре.</p>')

    role_color = {
        'Domain': '#222', 'ASN': '#6a1b9a', 'IP': '#1565c0', 'Provider': '#2e7d32',
        'Cloud': '#e65100', 'Region': '#00838f',
    }
    hops = []
    for i, hop in enumerate(chain):
        if i:
            hops.append('<span style="color:#aaa;margin:0 6px;">→</span>')
        color = role_color.get(hop['role'], '#555')
        hops.append(
            f'<span style="display:inline-block;border:1px solid {color};'
            f'border-radius:6px;padding:3px 10px;margin:2px 0;font-size:12px;'
            f'color:{color};white-space:nowrap;">'
            f'<b style="font-size:10px;opacity:.7;">{e(hop["role"])}</b><br>'
            f'{e(str(hop["value"]))}</span>'
        )
    chain_html = (f'<div style="display:flex;flex-wrap:wrap;align-items:center;">'
                  f'{"".join(hops)}</div>')

    rows = []
    for label, key in (('ASN', 'asn'), ('Provider', 'provider'),
                       ('Cloud', 'cloud'), ('ISP', 'isp'),
                       ('Region', 'region'), ('Location', 'location')):
        val = infra.get(key)
        if val:
            rows.append(
                f'<tr><td style="color:#666;padding:1px 12px 1px 0;">{e(label)}</td>'
                f'<td>{e(str(val))}</td></tr>'
            )
    table = (f'<table style="font-size:12px;margin-top:6px;">{"".join(rows)}</table>'
             if rows else '')
    return chain_html + table
