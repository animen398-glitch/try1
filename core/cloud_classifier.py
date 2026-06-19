"""core/cloud_classifier.py
Cloud-provider classification — pure, offline, table-driven.

The platform already collects the hosting-vendor signal in three separate forms and
never normalised them into one answer:

  * the recon **provider / ASN** string (``infrastructure.provider`` / ``asn_name`` —
    ``"Amazon.com, Inc."`` / ``"AS16509"``);
  * **CDN technologies** from ``tech_fingerprint`` (a CloudFront / Cloudflare header);
  * the **takeover-service CNAME** from ``subdomain_active`` (``*.amazonaws.com``).

This module is that single normaliser: a pure substring/regex table over signals that
are *already in the report*, turning any of them into a canonical cloud name (AWS /
Google Cloud / Microsoft Azure / Cloudflare / …) with a confidence reflecting how
direct the signal is. No new network call and no dependency (architectural invariants
I1/I5); nothing here feeds the risk score — it is a display/derive layer, like
exposure/criticality. Unknown stays unknown: a no-match returns ``{}`` (we never guess
a cloud from nothing).
"""

from typing import Dict, List, Optional

# Each signature maps the strongest available signal to a canonical cloud name.
#   keywords — substrings matched against the provider / ASN-name string
#   asn      — exact ASN numbers (the most authoritative offline signal)
#   tech     — CDN technology names (lower-cased) from tech_fingerprint
#   cname    — substrings of a takeover-service / hosting CNAME
# Order matters only on a score tie (first wins): keep the hyperscalers first.
_CLOUD_SIGNATURES: List[Dict] = [
    {'cloud': 'AWS',
     'keywords': ['amazon', 'aws', 'amazon technologies', 'amazon data services'],
     'asn': ['as16509', 'as14618', 'as7224', 'as8987'],
     'tech': ['amazon cloudfront'],
     'cname': ['amazonaws.com', 'awsdns', '.s3.', 's3-website', 'cloudfront.net',
               'elb.amazonaws.com', 'awsglobalaccelerator.com']},
    {'cloud': 'Google Cloud',
     'keywords': ['google'],
     'asn': ['as15169', 'as396982', 'as139070', 'as19527'],
     'tech': [],
     'cname': ['googleusercontent.com', 'appspot.com', 'storage.googleapis.com',
               'ghs.google', 'googlehosted.com', 'run.app']},
    {'cloud': 'Microsoft Azure',
     'keywords': ['microsoft', 'azure'],
     'asn': ['as8075', 'as8068', 'as12076'],
     'tech': [],
     'cname': ['azurewebsites.net', 'cloudapp.net', 'azureedge.net',
               'trafficmanager.net', 'azure-api.net', 'azurefd.net',
               'blob.core.windows.net', 'cloudapp.azure.com']},
    {'cloud': 'Cloudflare',
     'keywords': ['cloudflare'],
     'asn': ['as13335', 'as209242'],
     'tech': ['cloudflare'],
     'cname': ['cloudflare.net', 'cloudflare.com', 'cdn.cloudflare']},
    {'cloud': 'Fastly',
     'keywords': ['fastly'],
     'asn': ['as54113'],
     'tech': ['fastly'],
     'cname': ['fastly.net', 'fastlylb.net']},
    {'cloud': 'Akamai',
     'keywords': ['akamai'],
     'asn': ['as20940', 'as16625', 'as12222'],
     'tech': ['akamai'],
     'cname': ['akamai.net', 'akamaiedge.net', 'akamaized.net', 'edgekey.net',
               'edgesuite.net']},
    {'cloud': 'DigitalOcean',
     'keywords': ['digitalocean'],
     'asn': ['as14061'],
     'tech': [],
     'cname': ['digitaloceanspaces.com', 'ondigitalocean.app']},
    {'cloud': 'Oracle Cloud',
     'keywords': ['oracle'],
     'asn': ['as31898', 'as7160'],
     'tech': [],
     'cname': ['oraclecloud.com']},
    {'cloud': 'Linode',
     'keywords': ['linode', 'akamai connected cloud'],
     'asn': ['as63949'],
     'tech': [],
     'cname': ['linode.com', 'linodeobjects.com', 'members.linode.com']},
    {'cloud': 'Hetzner',
     'keywords': ['hetzner'],
     'asn': ['as24940', 'as213230'],
     'tech': [],
     'cname': ['your-server.de', 'hetzner.com']},
    {'cloud': 'OVH',
     'keywords': ['ovh'],
     'asn': ['as16276'],
     'tech': [],
     'cname': ['ovh.net', 'ovh.com']},
    {'cloud': 'Vercel',
     'keywords': ['vercel'],
     'asn': [],
     'tech': ['vercel'],
     'cname': ['vercel-dns.com', 'vercel.app', 'vercel.com']},
    {'cloud': 'Netlify',
     'keywords': ['netlify'],
     'asn': [],
     'tech': ['netlify'],
     'cname': ['netlify.app', 'netlify.com']},
    {'cloud': 'GitHub Pages',
     'keywords': [],
     'asn': [],
     'tech': [],
     'cname': ['github.io', 'githubusercontent.com']},
]

# Confidence per signal kind — an exact ASN number is the most authoritative offline
# signal; a vendor/CDN/CNAME name is strong but softer.
_CONF_ASN = 90
_CONF_KEYWORD = 80
_CONF_TECH = 75
_CONF_CNAME = 70


def _norm(s) -> str:
    return str(s or '').strip().lower()


def _tech_names(technologies) -> List[str]:
    out: List[str] = []
    for t in technologies or []:
        name = t.get('name') if isinstance(t, dict) else t
        n = _norm(name)
        if n:
            out.append(n)
    return out


def classify_cloud(provider: str = '', asn_name: str = '', asn: str = '',
                   technologies=None, cname: str = '') -> Dict:
    """Classify the hosting cloud from signals already in the report (pure).

    Matches, strongest-first: an exact ``asn`` number, then a ``provider``/``asn_name``
    keyword, then a CDN ``technologies`` name, then a hosting/takeover ``cname``
    substring. Returns ``{cloud, confidence, evidence}`` for the best match, or ``{}``
    when nothing matches (unknown stays unknown — no guessing). Offline, no network,
    no dependency; not a risk-score input."""
    asn_l = _norm(asn)
    text = ' '.join(p for p in (_norm(provider), _norm(asn_name)) if p)
    techs = _tech_names(technologies)
    cname_l = _norm(cname)

    best: Optional[tuple] = None   # (score, cloud, evidence)
    for sig in _CLOUD_SIGNATURES:
        score, evidence = 0, ''
        if asn_l and asn_l in sig['asn']:
            score, evidence = _CONF_ASN, f'ASN {asn}'
        elif text and any(k in text for k in sig['keywords']):
            score, evidence = _CONF_KEYWORD, f'provider «{provider or asn_name}»'
        elif techs and any(t in techs for t in sig['tech']):
            hit = next(t for t in sig['tech'] if t in techs)
            score, evidence = _CONF_TECH, f'CDN {hit}'
        elif cname_l and any(c in cname_l for c in sig['cname']):
            score, evidence = _CONF_CNAME, f'CNAME {cname}'
        if score and (best is None or score > best[0]):
            best = (score, sig['cloud'], evidence)

    if best is None:
        return {}
    return {'cloud': best[1], 'confidence': best[0], 'evidence': best[2]}
