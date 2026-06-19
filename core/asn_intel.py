"""core/asn_intel.py
Active ASN / netblock intelligence — Domain → ASN → IP → CIDR + co-hosted hosts.

Where ``core/infrastructure.py`` only *surfaces* the ASN/IP already in the recon
GeoIP blob (offline, no network), this module goes one hop further with **active**
lookups against keyless, official sources:

  * **IP → CIDR / range** via RDAP (``rdap.org``) — the allocated netblock.
  * **ASN → announced prefixes** via RIPEstat — every CIDR the ASN advertises
    (capped; large ASNs announce hundreds).
  * **IP → co-hosted domains** via HackerTarget reverse-IP (keyless, rate-limited
    → best-effort; degrades silently when the free quota is exhausted).

This is active recon, so it is strictly opt-in in the pipeline. Following the
OSINT-module pattern (dns_intel): the network is a single injectable seam
(``_get_text``), every lookup is TTL-cached, and the aggregation/parsing is pure
and offline-testable (architectural invariant I5). stdlib only (urllib + json),
no new dependency (I1); ``render_html`` is a self-contained offline fragment (I2).
"""

import html
import json
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import quote

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text
from utils.scan_cache import TTLCache

_RDAP_IP_URL = 'https://rdap.org/ip/{ip}'
_RIPE_PREFIXES_URL = ('https://stat.ripe.net/data/announced-prefixes/'
                      'data.json?resource={asn}')
_REVERSE_IP_URL = 'https://api.hackertarget.com/reverseiplookup/?q={ip}'

_FETCH_TIMEOUT = 12.0
# Caps so a huge ASN / shared host can't bloat the report or memory.
PREFIX_CAP = 50
NEIGHBOR_CAP = 100

# Session TTL cache (mirrors recon's GeoIP cache) so re-scanning a host within
# the hour doesn't re-hit the external services.
_CACHE = TTLCache(ttl_seconds=3600)

_HOST_RE = re.compile(r'^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$')


def clear_cache() -> int:
    """Drop the cached lookups; returns how many entries were cleared (for the
    Settings 'clear cache' action, like recon's clear_geo_cache)."""
    n = len(_CACHE)
    _CACHE.clear()
    return n


# ── network seam (injectable; never hit in tests) ─────────────────────────────

def _get_text(url: str, timeout: float = _FETCH_TIMEOUT,
              profile: str = 'chrome_windows') -> str:
    """GET ``url`` and return decoded text, or '' on any failure.

    The single network seam — callers inject a fake in tests so the pure parsing
    and aggregation never touch the network."""
    try:
        req = SessionBuilder(profile).make_request(url)
        req.add_header('Accept',
                       'application/json, application/rdap+json, text/plain, */*')
        return urlopen_text(req, timeout, attempts=2)
    except Exception:   # noqa: BLE001 — a failed lookup degrades, never aborts
        return ''


# ── pure parsers ──────────────────────────────────────────────────────────────

def _parse_rdap(text: str) -> Dict:
    """RDAP IP response → ``{cidr, range, name, handle}`` ('' fields on miss)."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return {}
    if not isinstance(doc, dict):
        return {}
    cidr = ''
    cidrs = doc.get('cidr0_cidrs')
    if isinstance(cidrs, list) and cidrs and isinstance(cidrs[0], dict):
        c = cidrs[0]
        prefix = c.get('v4prefix') or c.get('v6prefix')
        length = c.get('length')
        if prefix and length is not None:
            cidr = f'{prefix}/{length}'
    start, end = doc.get('startAddress'), doc.get('endAddress')
    rng = f'{start} – {end}' if start and end else ''
    name = doc.get('name') or ''
    handle = doc.get('handle') or ''
    if not (cidr or rng or name):
        return {}
    return {'cidr': cidr, 'range': rng, 'name': name, 'handle': handle}


def _parse_ripe_prefixes(text: str) -> Dict:
    """RIPEstat announced-prefixes response → ``{prefixes:[...], count:int}``."""
    empty = {'prefixes': [], 'count': 0}
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return empty
    data = doc.get('data') if isinstance(doc, dict) else None
    items = data.get('prefixes') if isinstance(data, dict) else None
    if not isinstance(items, list):
        return empty
    prefixes = [p.get('prefix') for p in items
                if isinstance(p, dict) and p.get('prefix')]
    return {'prefixes': prefixes, 'count': len(prefixes)}


def _parse_reverse_ip(text: str) -> Dict:
    """HackerTarget reverse-IP plaintext → ``{neighbors:[...], count:int}``.

    The free endpoint returns newline-separated hostnames, or a short error /
    'API count exceeded' line on the rate limit — both degrade to empty."""
    empty = {'neighbors': [], 'count': 0}
    if not text:
        return empty
    low = text.lower()
    if ('api count exceeded' in low or low.startswith('error')
            or 'no records found' in low):
        return empty
    seen, hosts = set(), []
    for line in text.splitlines():
        host = line.strip().lower()
        if host and _HOST_RE.match(host) and host not in seen:
            seen.add(host)
            hosts.append(host)
    return {'neighbors': hosts, 'count': len(hosts)}


# ── cached lookups (each wraps one parser + the network seam) ─────────────────

def fetch_cidr(ip: str, *, get_text: Optional[Callable] = None) -> Dict:
    if not ip:
        return {}
    get = get_text or _get_text
    return _CACHE.get_or_compute(
        ('cidr', ip), lambda: _parse_rdap(get(_RDAP_IP_URL.format(ip=quote(ip)))))


def fetch_asn_prefixes(asn: str, *, get_text: Optional[Callable] = None) -> Dict:
    if not asn:
        return {'prefixes': [], 'count': 0}
    get = get_text or _get_text
    return _CACHE.get_or_compute(
        ('prefixes', asn),
        lambda: _parse_ripe_prefixes(get(_RIPE_PREFIXES_URL.format(asn=quote(asn)))))


def fetch_reverse_ip(ip: str, *, get_text: Optional[Callable] = None) -> Dict:
    if not ip:
        return {'neighbors': [], 'count': 0}
    get = get_text or _get_text
    return _CACHE.get_or_compute(
        ('reverse', ip),
        lambda: _parse_reverse_ip(get(_REVERSE_IP_URL.format(ip=quote(ip)))))


# ── aggregation (pure given the fetchers) ─────────────────────────────────────

def build_asn_intel(infra: Dict, *, cidr_fetch: Optional[Callable] = None,
                    prefixes_fetch: Optional[Callable] = None,
                    reverse_fetch: Optional[Callable] = None) -> Dict:
    """Compose active netblock intel from a recon-derived ``infra`` dict.

    ``infra`` is what ``infrastructure.build_infrastructure`` returns (needs
    ``ip`` and/or ``asn``). The three fetchers are injected for testing; by
    default they are the cached network lookups. Returns a status dict with the
    discovered netblock, ASN prefixes and co-hosted hosts (both capped).
    """
    ip = (infra or {}).get('ip')
    asn = (infra or {}).get('asn')
    if not ip and not asn:
        return {'status': 'Skipped', 'reason': 'no ip/asn', 'ip': ip, 'asn': asn,
                'cidr': '', 'range': '', 'netname': '',
                'prefixes': [], 'prefix_count': 0,
                'neighbors': [], 'neighbor_count': 0}

    cidr_fetch = cidr_fetch or fetch_cidr
    prefixes_fetch = prefixes_fetch or fetch_asn_prefixes
    reverse_fetch = reverse_fetch or fetch_reverse_ip

    net = cidr_fetch(ip) if ip else {}
    pref = prefixes_fetch(asn) if asn else {'prefixes': [], 'count': 0}
    rev = reverse_fetch(ip) if ip else {'neighbors': [], 'count': 0}

    prefixes: List[str] = pref.get('prefixes', []) or []
    neighbors: List[str] = rev.get('neighbors', []) or []
    return {
        'status': 'Success',
        'ip': ip, 'asn': asn, 'asn_name': (infra or {}).get('asn_name', ''),
        'cidr': net.get('cidr', ''), 'range': net.get('range', ''),
        'netname': net.get('name', ''),
        'prefixes': prefixes[:PREFIX_CAP],
        'prefix_count': pref.get('count', len(prefixes)),
        'neighbors': neighbors[:NEIGHBOR_CAP],
        'neighbor_count': rev.get('count', len(neighbors)),
    }


# ── related assets (co-hosted, derive-on-read view) ───────────────────────────
#
# The last hop of the infra chain (Domain → … → Related Assets): the reverse-IP
# neighbours are *other* domains sharing our IP. They are a DISPLAY view, never
# promoted to owned AssetStore rows — a co-hosted domain is not our asset (promoting
# it would bloat the inventory and invite false ownership/takeover signals). So this
# is pure derive-on-read over the data ``build_asn_intel`` already collected, with our
# own hosts filtered out so "related" means genuinely external.

def related_assets(intel: Optional[Dict], *, own_hosts=()) -> Dict:
    """Structured co-hosted related-assets view from an ``asn_intel`` result (pure).

    ``intel`` is :func:`build_asn_intel`'s dict; ``own_hosts`` is our domain +
    subdomains, filtered out so the result is only *external* domains sharing our IP.
    Returns ``{shared_ip, related:[{host, shared_ip}], count, total}`` (``total`` is
    the raw neighbour count before our-host filtering)."""
    if not isinstance(intel, dict):
        return {'shared_ip': '', 'related': [], 'count': 0, 'total': 0}
    own = {str(h).strip().lower().rstrip('.') for h in (own_hosts or []) if h}
    shared_ip = intel.get('ip') or ''
    neighbors = intel.get('neighbors') or []
    seen, hosts = set(), []
    for n in neighbors:
        host = str(n or '').strip().lower().rstrip('.')
        if host and host not in own and host not in seen:
            seen.add(host)
            hosts.append(host)
    hosts.sort()
    return {'shared_ip': shared_ip,
            'related': [{'host': h, 'shared_ip': shared_ip} for h in hosts],
            'count': len(hosts),
            'total': intel.get('neighbor_count', len(neighbors))}


def _own_hosts_from_report(report: Optional[Dict]) -> set:
    """Our own hosts in a scan report — the apex domain + every probed subdomain —
    so :func:`related_assets` can exclude them from the co-hosted view."""
    out = set()
    dom = (report or {}).get('domain')
    if dom:
        out.add(str(dom).strip().lower().rstrip('.'))
    sub = (report or {}).get('phases', {}).get('subdomains', {})
    data = sub.get('data', {}) if isinstance(sub, dict) else {}
    for e in (data.get('results') or []):
        if isinstance(e, dict) and e.get('subdomain'):
            out.add(str(e['subdomain']).strip().lower().rstrip('.'))
    return out


def related_assets_from_report(report: Optional[Dict]) -> Dict:
    """Derive the co-hosted related-assets view from a scan report (pure).

    Reads the (opt-in) ``asn_intel`` phase's neighbours and filters out our own
    hosts. Empty view when the phase didn't run."""
    asn = (report or {}).get('phases', {}).get('asn_intel', {})
    data = (asn.get('data', {}) if isinstance(asn, dict)
            and asn.get('status') == 'Success' else {})
    return related_assets(data or {}, own_hosts=_own_hosts_from_report(report))


def load_related_assets(project) -> Dict:
    """A project's latest-scan co-hosted related assets (thin report reader).

    ``project`` is a :class:`core.project.Project` (report-based, like
    ``intelligence.load_accuracy``). Offline, read-only, guarded — a missing
    report degrades to an empty view."""
    empty = {'shared_ip': '', 'related': [], 'count': 0, 'total': 0}
    try:
        if project is None:
            return dict(empty)
        latest = project.latest_scan()
        scan_id = latest.get('id') if isinstance(latest, dict) else None
        report = project.load_scan_report(scan_id) if scan_id else None
        if not isinstance(report, dict):
            return dict(empty)
        return related_assets_from_report(report)
    except Exception as e:  # noqa: BLE001 — surface as data, never crash a caller
        return {**empty, 'error': str(e)}


# ── offline render ────────────────────────────────────────────────────────────

def render_html(intel: Optional[Dict]) -> str:
    """Render the active netblock intel as a self-contained offline fragment."""
    e = html.escape
    intel = intel or {}
    if intel.get('status') != 'Success':
        return ('<p style="font-size:13px;color:#999;">'
                'Активная ASN-разведка не выполнялась.</p>')

    rows = []
    for label, key in (('Netblock (CIDR)', 'cidr'), ('Диапазон', 'range'),
                       ('Netname', 'netname'), ('ASN', 'asn')):
        val = intel.get(key)
        if val:
            rows.append(
                f'<tr><td style="color:#666;padding:1px 12px 1px 0;'
                f'white-space:nowrap;">{e(label)}</td><td>{e(str(val))}</td></tr>')
    table = (f'<table style="font-size:12px;margin:4px 0;">{"".join(rows)}</table>'
             if rows else '')

    def _chips(items, total, color):
        chips = ''.join(
            f'<span style="display:inline-block;border:1px solid {color};'
            f'border-radius:10px;padding:1px 8px;margin:2px;font-size:11px;'
            f'color:{color};">{e(str(it))}</span>' for it in items)
        extra = total - len(items)
        if extra > 0:
            chips += (f'<span style="font-size:11px;color:#888;margin-left:4px;">'
                      f'… ещё {extra}</span>')
        return chips

    blocks = [table]
    prefixes = intel.get('prefixes') or []
    if prefixes:
        blocks.append(
            f'<div style="margin-top:6px;"><b style="font-size:12px;">'
            f'Префиксы ASN ({intel.get("prefix_count", len(prefixes))})</b><br>'
            f'{_chips(prefixes, intel.get("prefix_count", len(prefixes)), "#6a1b9a")}'
            f'</div>')
    neighbors = intel.get('neighbors') or []
    if neighbors:
        blocks.append(
            f'<div style="margin-top:6px;"><b style="font-size:12px;">'
            f'Со-хостящиеся домены ({intel.get("neighbor_count", len(neighbors))})'
            f'</b><br>'
            f'{_chips(neighbors, intel.get("neighbor_count", len(neighbors)), "#1565c0")}'
            f'</div>')
    if len(blocks) == 1 and not table:
        return ('<p style="font-size:13px;color:#999;">'
                'Активная ASN-разведка не дала данных.</p>')
    return ''.join(blocks)
