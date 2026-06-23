"""core/email_intel.py
Email Intelligence — harvest e-mail addresses a target exposes and group them
(roadmap #13, OSINT).

Pulls addresses from the homepage HTML (inline JS included), ``robots.txt`` and
``sitemap.xml``, filters out the usual false positives (asset filenames,
placeholder domains, version strings), then groups them on-domain vs external
and by role (security/admin/support/info/…).

Invariants:
  * I1 — stdlib only (re + urllib via SessionBuilder).
  * I5 — the network fetch (``_fetch_text``) is separated from the pure
    extraction/classification (``extract_emails`` / ``classify``) and injectable
    into ``discover``, so tests never hit the network.
"""

import html
import re
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

_FETCH_TIMEOUT = 10.0

# Conservative address pattern: a real TLD ([a-z]{2,}) keeps version strings
# like "react@18.2.0" out (their "TLD" is numeric).
_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Domains/locals that are placeholders or library noise, never real contacts.
_NOISE_DOMAINS = {
    'example.com', 'example.org', 'example.net', 'domain.com', 'email.com',
    'yourdomain.com', 'sentry.io', 'wixpress.com', 'sentry.wixpress.com',
    'schema.org', 'w3.org', 'sentry-next.wixpress.com',
}
# Address "domains" that are really asset filenames (sprite@2x.png, etc.).
_ASSET_EXTS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.css',
               '.js', '.ico', '.woff', '.woff2', '.ttf')

# Role grouping by local-part keyword (first match wins; else "personal").
ROLE_RULES = {
    'security': ('security', 'abuse', 'soc', 'csirt', 'psirt', 'cert'),
    'admin': ('admin', 'administrator', 'root', 'webmaster', 'hostmaster',
              'postmaster', 'sysadmin'),
    'support': ('support', 'help', 'helpdesk', 'service'),
    'sales': ('sales', 'billing', 'accounts', 'orders', 'payments'),
    'careers': ('jobs', 'careers', 'hr', 'recruiting', 'recruitment'),
    'press': ('press', 'media', 'pr@', 'marketing'),
    'noreply': ('noreply', 'no-reply', 'donotreply', 'do-not-reply', 'bounce',
                'mailer-daemon'),
    'info': ('info', 'contact', 'hello', 'enquiries', 'inquiries', 'office'),
}


# ── network (injectable; kept out of the pure extractor) ──────────────────────

def _fetch_text(url: str, timeout: float = _FETCH_TIMEOUT,
                profile: str = 'chrome_windows') -> str:
    """GET ``url`` as text, or '' on any failure."""
    try:
        req = SessionBuilder(profile).make_request(url)
        return urlopen_text(req, timeout, attempts=1)
    except Exception:
        return ''


# ── pure extraction / classification ──────────────────────────────────────────

def _is_noise(email: str) -> bool:
    local, _, domain = email.partition('@')
    if domain in _NOISE_DOMAINS:
        return True
    if domain.endswith(_ASSET_EXTS):
        return True
    # u00xx unicode-escape fragments sometimes look like locals.
    if local.startswith(('u00', 'x')) and local[1:4].isdigit():
        return True
    return False


def extract_emails(text: str) -> Set[str]:
    """All plausible e-mail addresses in ``text`` (lowercased, de-noised, pure)."""
    found = set()
    for m in _EMAIL_RE.findall(text or ''):
        e = m.lower().strip('.')
        if not _is_noise(e):
            found.add(e)
    return found


def role_of(email: str) -> str:
    """The role bucket for an address from its local part."""
    local = email.split('@', 1)[0].lower()
    for role, keys in ROLE_RULES.items():
        if any(k.strip('@') in local for k in keys):
            return role
    return 'personal'


def classify(emails, domain: str) -> Dict:
    """Group addresses on-domain vs external and by role (pure).

    On-domain = the address domain equals ``domain`` or is a subdomain of it."""
    base = (domain or '').lower().lstrip('.')
    uniq = sorted({e.lower() for e in emails})
    on_domain: List[str] = []
    external: List[str] = []
    for e in uniq:
        edom = e.split('@', 1)[1]
        if base and (edom == base or edom.endswith('.' + base)):
            on_domain.append(e)
        else:
            external.append(e)
    roles: Dict[str, List[str]] = {}
    for e in uniq:
        roles.setdefault(role_of(e), []).append(e)
    return {'total': len(uniq), 'on_domain': on_domain, 'external': external,
            'roles': roles}


# ── discovery (fetch + extract + classify) ────────────────────────────────────

def target_root_and_domain(target: str) -> Tuple[str, str]:
    """Split a target (bare host or full URL) into ``(root URL, apex domain)``.

    A leading ``www.`` is stripped from the domain so addresses at the apex (e.g.
    ``info@gnu.org``) count as on-domain even when the site is served from www.
    Shared with employee_intel, which harvests from the same target shape."""
    parts = urlparse(target if '://' in target else 'https://' + target)
    root = f'{parts.scheme}://{parts.netloc}'
    domain = parts.netloc.split(':')[0].removeprefix('www.')
    return root, domain


def discover(target: str, fetch: Optional[Callable] = None,
             timeout: float = _FETCH_TIMEOUT,
             profile: str = 'chrome_windows') -> Dict:
    """Harvest e-mails from a target's homepage, robots.txt and sitemap.xml.

    ``fetch(url)`` overrides the default getter (tests inject a fake). Returns
    ``{status, domain, sources, ...classify}``."""
    root, domain = target_root_and_domain(target)
    getter = fetch or (lambda u: _fetch_text(u, timeout, profile))

    sources = {'homepage': root, 'robots': f'{root}/robots.txt',
               'sitemap': f'{root}/sitemap.xml'}
    emails: Set[str] = set()
    scanned: List[str] = []
    for label, url in sources.items():
        text = getter(url)
        if text:
            scanned.append(label)
            emails |= extract_emails(text)

    if not emails:
        return {'status': 'No emails', 'domain': domain, 'sources': scanned,
                'total': 0, 'on_domain': [], 'external': [], 'roles': {}}

    result = classify(emails, domain)
    result.update({'status': 'Success', 'domain': domain, 'sources': scanned})
    return result


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

_ROLE_LABELS = {'security': 'Security', 'admin': 'Admin', 'support': 'Support',
                'sales': 'Sales', 'careers': 'Careers', 'press': 'Press',
                'noreply': 'No-reply', 'info': 'Info', 'personal': 'Личные'}


def render_html(data: Dict) -> str:
    """Render the harvested e-mails as an offline HTML fragment."""
    e = html.escape
    if not data or data.get('status') != 'Success':
        return '<p style="font-size:13px;color:#999;">E-mail не найдены</p>'

    head = (f'<p style="font-size:13px;">Найдено адресов: '
            f'<b>{e(str(data.get("total", 0)))}</b> '
            f'(на домене: {e(str(len(data.get("on_domain", []))))}, '
            f'внешних: {e(str(len(data.get("external", []))))}; '
            f'источники: {e(", ".join(data.get("sources", [])) or "—")})</p>')

    blocks = []
    for role, addrs in sorted(data.get('roles', {}).items(),
                              key=lambda kv: -len(kv[1])):
        items = ''.join(
            f'<li style="margin:1px 0;font-family:monospace;font-size:12px;">'
            f'{e(a)}</li>' for a in addrs[:30])
        blocks.append(
            f'<div style="margin:6px 0;"><b style="font-size:12px;">'
            f'{e(_ROLE_LABELS.get(role, role))} ({len(addrs)})</b>'
            f'<ul style="margin:2px 0;">{items}</ul></div>')
    return head + ''.join(blocks)
