"""core/ct_history.py
Certificate Transparency History — every certificate ever logged for a domain
and what that history reveals (roadmap #13, OSINT).

The subdomain scanner already mines crt.sh, but only for *names* — it throws
away the temporal and issuer metadata. This module keeps it: who issued certs
for the domain (CAs), the validity windows, when the domain first/last appeared
in the logs, which certs are wildcards, and what was issued recently. That
timeline is an OSINT signal in its own right (infrastructure churn, a new CA
appearing, a freshly minted cert for a sensitive name).

Informational only — like Email/Employee Intelligence it feeds the report and
Scan Diff, but does not push findings into the risk engine.

Invariants:
  * I1 — stdlib only (json + datetime + urllib via SessionBuilder).
  * I5 — the network fetch (``_fetch_crtsh``) is separated from the pure
    analysis (``analyze``, with an injectable ``now``) and injectable into
    ``discover``, so tests never hit the network and are time-deterministic.
"""

import html
import json
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

_FETCH_TIMEOUT = 15.0
# crt.sh wildcard query — every identity logged under the domain, as JSON. The
# same endpoint the subdomain scanner uses, asked for the whole cert record.
_CRTSH_URL = 'https://crt.sh/?q=%.{domain}&output=json'

# "Recent" issuance window and the cap on the per-cert list we keep/serialize
# (aggregates are computed over every entry; only the detail list is bounded).
_RECENT_DAYS = 90
_CERT_CAP = 100


# ── network (injectable; kept out of the pure analyzer) ───────────────────────

def _fetch_crtsh(domain: str, timeout: float = _FETCH_TIMEOUT,
                 profile: str = 'chrome_windows') -> List[Dict]:
    """Fetch crt.sh's JSON cert list for ``domain``, or [] on any failure."""
    url = _CRTSH_URL.format(domain=domain)
    try:
        req = SessionBuilder(profile).make_request(url)
        req.add_header('Accept', 'application/json')
        data = json.loads(urlopen_text(req, timeout, attempts=2))
    except Exception:
        return []
    return data if isinstance(data, list) else []


# ── pure parsing helpers ──────────────────────────────────────────────────────

def _parse_dt(value) -> Optional[datetime]:
    """Parse a crt.sh ISO timestamp (with/without fractional seconds), or None."""
    if not value:
        return None
    s = str(value).strip().replace(' ', 'T').rstrip('Z')
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _issuer_label(issuer_name: str) -> str:
    """A readable CA name from a crt.sh issuer DN (prefer O=, then CN=)."""
    parts = {}
    for chunk in str(issuer_name or '').split(','):
        k, _, v = chunk.strip().partition('=')
        if v and k.upper() not in parts:
            parts[k.upper()] = v.strip()
    return parts.get('O') or parts.get('CN') or (str(issuer_name).strip() or '—')


def _in_domain_names(name_value: str, base: str):
    """(names, had_wildcard) for the in-domain SANs of one crt.sh entry."""
    names = set()
    wildcard = False
    for raw in str(name_value or '').splitlines():
        n = raw.strip().lower()
        if not n:
            continue
        if n.startswith('*.'):
            wildcard = True
            n = n[2:]
        if base and (n == base or n.endswith('.' + base)):
            names.add(n)
    return names, wildcard


# ── pure analysis ─────────────────────────────────────────────────────────────

def analyze(entries: List[Dict], domain: str,
            now: Optional[datetime] = None) -> Dict:
    """Summarize a domain's CT history from crt.sh entries (pure).

    ``now`` (default ``datetime.utcnow()``) anchors the recent/active windows so
    tests are deterministic. De-dupes by crt.sh ``id``."""
    now = now or datetime.utcnow()
    base = (domain or '').lower().lstrip('.')
    recent_cutoff = now - timedelta(days=_RECENT_DAYS)

    certs: Dict = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        cid = e.get('id')
        if cid in certs:
            continue
        names, wildcard = _in_domain_names(e.get('name_value', ''), base)
        if not names:
            continue
        nb = _parse_dt(e.get('not_before'))
        na = _parse_dt(e.get('not_after'))
        certs[cid] = {
            'id': cid,
            'issuer': _issuer_label(e.get('issuer_name', '')),
            'not_before': nb.isoformat() if nb else '',
            'not_after': na.isoformat() if na else '',
            'names': sorted(names),
            'wildcard': wildcard,
            '_nb': nb, '_na': na,
        }

    if not certs:
        return {'total_certs': 0, 'name_count': 0, 'names': [], 'issuers': [],
                'first_seen': '', 'last_seen': '', 'recent_count': 0,
                'active_count': 0, 'expired_count': 0, 'wildcards': [],
                'certs': []}

    all_names = sorted({n for c in certs.values() for n in c['names']})
    wildcards = sorted({n for c in certs.values() if c['wildcard']
                        for n in c['names']})

    issuer_counts: Dict[str, int] = {}
    for c in certs.values():
        issuer_counts[c['issuer']] = issuer_counts.get(c['issuer'], 0) + 1
    issuers = [{'ca': ca, 'count': n} for ca, n in
               sorted(issuer_counts.items(), key=lambda kv: (-kv[1], kv[0]))]

    nbs = [c['_nb'] for c in certs.values() if c['_nb']]
    first_seen = min(nbs).isoformat() if nbs else ''
    last_seen = max(nbs).isoformat() if nbs else ''
    recent_count = sum(1 for c in certs.values()
                       if c['_nb'] and c['_nb'] >= recent_cutoff)
    active_count = sum(1 for c in certs.values()
                       if c['_na'] and c['_na'] > now)
    expired_count = sum(1 for c in certs.values()
                        if c['_na'] and c['_na'] <= now)

    # Most-recent-first detail list, capped; drop the private datetime helpers.
    ordered = sorted(certs.values(),
                     key=lambda c: (c['_nb'] or datetime.min), reverse=True)
    cert_list = [{k: v for k, v in c.items() if not k.startswith('_')}
                 for c in ordered[:_CERT_CAP]]

    return {
        'total_certs': len(certs),
        'name_count': len(all_names),
        'names': all_names,
        'issuers': issuers,
        'first_seen': first_seen,
        'last_seen': last_seen,
        'recent_count': recent_count,
        'active_count': active_count,
        'expired_count': expired_count,
        'wildcards': wildcards,
        'certs': cert_list,
    }


# ── discovery (fetch + analyze) ───────────────────────────────────────────────

def discover(target: str, fetch: Optional[Callable] = None,
             now: Optional[datetime] = None, timeout: float = _FETCH_TIMEOUT,
             profile: str = 'chrome_windows') -> Dict:
    """Pull a domain's Certificate Transparency history from crt.sh.

    ``fetch(domain)`` overrides the default getter (tests inject a fake) and
    returns the raw crt.sh entry list. Returns ``{status, domain, ...analyze}``."""
    netloc = urlparse(target if '://' in target else 'https://' + target).netloc \
        or target
    domain = netloc.split(':')[0].removeprefix('www.')
    getter = fetch or (lambda d: _fetch_crtsh(d, timeout, profile))

    entries = getter(domain)
    analysis = analyze(entries or [], domain, now=now)
    if analysis['total_certs'] == 0:
        return {'status': 'No certificates', 'domain': domain, **analysis}
    return {'status': 'Success', 'domain': domain, **analysis}


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

def _fmt_date(iso: str) -> str:
    """YYYY-MM-DD from an ISO timestamp (or '—')."""
    return iso[:10] if iso else '—'


def render_html(data: Dict) -> str:
    """Render the CT history as an offline HTML fragment."""
    e = html.escape
    if not data or data.get('status') != 'Success':
        return ('<p style="font-size:13px;color:#999;">'
                'CT-сертификаты не найдены</p>')

    head = (f'<p style="font-size:13px;">Сертификатов в CT: '
            f'<b>{e(str(data.get("total_certs", 0)))}</b> '
            f'(имён: {e(str(data.get("name_count", 0)))}, '
            f'активных: {e(str(data.get("active_count", 0)))}, '
            f'за {_RECENT_DAYS} дн.: {e(str(data.get("recent_count", 0)))}; '
            f'история: {e(_fmt_date(data.get("first_seen", "")))} → '
            f'{e(_fmt_date(data.get("last_seen", "")))})</p>')

    issuers = data.get('issuers', [])
    irows = ''.join(
        f'<tr><td style="padding:1px 12px 1px 0;">{e(str(i.get("ca", "")))}</td>'
        f'<td style="color:#666;">{e(str(i.get("count", 0)))}</td></tr>'
        for i in issuers[:10])
    itable = (f'<p style="font-size:12px;margin:6px 0 2px;"><b>Центры '
              f'сертификации (CA)</b></p><table style="font-size:12px;">'
              f'{irows}</table>' if irows else '')

    certs = data.get('certs', [])
    crows = ''.join(
        f'<tr><td style="color:#666;padding:1px 10px 1px 0;white-space:nowrap;">'
        f'{e(_fmt_date(c.get("not_before", "")))}</td>'
        f'<td style="padding:1px 10px 1px 0;">{e(str(c.get("issuer", "")))}</td>'
        f'<td style="font-family:monospace;font-size:11px;word-break:break-all;">'
        f'{e(", ".join(c.get("names", [])[:4]))}'
        f'{" …" if len(c.get("names", [])) > 4 else ""}</td></tr>'
        for c in certs[:30])
    ctable = (f'<p style="font-size:12px;margin:8px 0 2px;"><b>Последние '
              f'сертификаты</b></p><table style="font-size:12px;'
              f'border-collapse:collapse;">{crows}</table>' if crows else '')

    return head + itable + ctable
