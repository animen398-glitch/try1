"""core/employee_intel.py
Employee Intelligence — the people a target exposes and the corporate e-mail
scheme that implies (roadmap #13, OSINT).

Harvests named individuals (+ their job title and any social links) from the
pages a company publishes about itself — homepage plus the usual team / about /
leadership paths — from two structured, low-noise sources:

  * schema.org ``Person`` objects in JSON-LD (``name`` / ``jobTitle`` / ``email``
    / ``sameAs``); and
  * personal ``mailto:`` addresses whose local part is a name pattern
    (``jane.smith@`` → Jane Smith), reusing email_intel's role filter so role
    mailboxes (info@, security@) are not mistaken for people.

When some people carry a real on-domain address, the module *infers the e-mail
format* the organisation uses ({first}.{last}, {f}{last}, …) from those
name↔address pairs, then fills in a probable address for the named people who
lack one — marked ``inferred`` so it is never confused with a harvested one. No
scheme is ever guessed without on-domain evidence (honesty over coverage).

Invariants:
  * I1 — stdlib only (html + json + re + urllib via SessionBuilder).
  * I5 — the network fetch (``_fetch_text``) is separated from the pure roster
    building (``extract_people`` / ``infer_format`` / ``build_roster``) and
    injectable into ``discover``, so tests never hit the network.
"""

import html
import json
import re
from typing import Callable, Dict, List, Optional, Tuple

from core.email_intel import role_of, target_root_and_domain
from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

_FETCH_TIMEOUT = 10.0

# Pages a company typically uses to introduce its people, relative to the root.
TEAM_PATHS = ('', '/about', '/about-us', '/team', '/our-team', '/people',
              '/leadership', '/staff', '/management', '/company/team')

# A personal mailto local part: two name tokens joined by . or _ (jane.smith,
# jane_smith). Single-token locals are too ambiguous to reconstruct a name.
_NAME_LOCAL_RE = re.compile(r'^([a-z]+)[._]([a-z]+)$')
_MAILTO_RE = re.compile(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})')
_LDJSON_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL)

# Candidate corporate e-mail formats, most specific / common first — the order
# is also the tie-break when several match the same name↔address pair.
_FORMATS = ('{first}.{last}', '{first}_{last}', '{f}.{last}', '{f}{last}',
            '{first}{last}', '{first}{l}', '{f}_{last}', '{first}', '{last}')


# ── network (injectable; kept out of the pure roster builder) ─────────────────

def _fetch_text(url: str, timeout: float = _FETCH_TIMEOUT,
                profile: str = 'chrome_windows') -> str:
    """GET ``url`` as text, or '' on any failure."""
    try:
        req = SessionBuilder(profile).make_request(url)
        return urlopen_text(req, timeout, attempts=1)
    except Exception:
        return ''


# ── name / e-mail helpers (pure) ──────────────────────────────────────────────

def _split_name(name: str) -> Tuple[str, str]:
    """(first, last) in lowercase ascii, or ('', '') when unusable.

    Keeps the first and last whitespace tokens (drops middle names/initials);
    strips anything that is not a letter so accents/punctuation don't leak into
    a generated local part."""
    tokens = [re.sub(r'[^a-z]', '', t.lower()) for t in (name or '').split()]
    tokens = [t for t in tokens if t]
    if not tokens:
        return '', ''
    if len(tokens) == 1:
        return tokens[0], ''
    return tokens[0], tokens[-1]


def _name_from_local(local: str) -> str:
    """Reconstruct a display name from a ``first.last`` local part, or ''."""
    m = _NAME_LOCAL_RE.match(local.lower())
    if not m:
        return ''
    return f'{m.group(1).capitalize()} {m.group(2).capitalize()}'


def _apply_format(fmt: str, first: str, last: str) -> str:
    return (fmt.replace('{first}', first).replace('{last}', last)
               .replace('{f}', first[:1]).replace('{l}', last[:1]))


def _match_format(first: str, last: str, local: str) -> Optional[str]:
    """The first format string that reproduces ``local`` for this name, or None."""
    local = local.lower()
    for fmt in _FORMATS:
        # Single-token formats only make sense with that token present.
        if '{last}' in fmt and not last:
            continue
        if fmt in ('{first}', '{f}{last}', '{first}{l}') and not first:
            continue
        if _apply_format(fmt, first, last) == local:
            return fmt
    return None


def infer_format(pairs: List[Tuple[str, str, str]]) -> Optional[str]:
    """Most common e-mail format among (first, last, local) pairs, or None.

    Pure: ``pairs`` are name↔local-part samples observed on the target domain."""
    counts: Dict[str, int] = {}
    for first, last, local in pairs:
        fmt = _match_format(first, last, local)
        if fmt:
            counts[fmt] = counts.get(fmt, 0) + 1
    if not counts:
        return None
    # Tie-break by _FORMATS order (earlier = more conventional).
    return max(counts, key=lambda f: (counts[f], -_FORMATS.index(f)))


def generate_email(name: str, fmt: Optional[str], domain: str) -> Optional[str]:
    """Apply an inferred ``fmt`` to ``name`` @ ``domain``; None without a format
    or a usable name (we never invent a scheme)."""
    if not fmt or not domain:
        return None
    first, last = _split_name(name)
    if not first:
        return None
    if '{last}' in fmt and not last:
        return None
    local = _apply_format(fmt, first, last)
    return f'{local}@{domain}' if local else None


# ── extraction (pure) ─────────────────────────────────────────────────────────

def _iter_jsonld(text: str):
    """Yield each parsed JSON-LD payload found in ``text`` (skips malformed)."""
    for blob in _LDJSON_RE.findall(text or ''):
        try:
            yield json.loads(blob)
        except Exception:
            continue


def _walk_persons(node, out: List[Dict]):
    """Collect schema.org Person objects from an arbitrarily nested JSON-LD node."""
    if isinstance(node, list):
        for item in node:
            _walk_persons(item, out)
        return
    if not isinstance(node, dict):
        return
    types = node.get('@type')
    types = types if isinstance(types, list) else [types]
    if any(str(t).lower() == 'person' for t in types) and node.get('name'):
        social = node.get('sameAs')
        social = social if isinstance(social, list) else (
            [social] if isinstance(social, str) else [])
        out.append({
            'name': str(node.get('name')).strip(),
            'title': str(node.get('jobTitle') or '').strip(),
            'email': (str(node.get('email')).strip().lower()
                      if node.get('email') else ''),
            'social': [str(s) for s in social if isinstance(s, str)],
        })
    # Recurse into common container keys (@graph, employee, member, …).
    for value in node.values():
        if isinstance(value, (list, dict)):
            _walk_persons(value, out)


def extract_people(text: str, domain: str) -> List[Dict]:
    """People named on a page (JSON-LD Person + personal mailto), pure.

    Returns raw ``{name, title, email, social}`` records (email may be '');
    deduping and format inference happen later in :func:`build_roster`."""
    people: List[Dict] = []
    for payload in _iter_jsonld(text):
        _walk_persons(payload, people)

    base = (domain or '').lower().lstrip('.')
    for addr in _MAILTO_RE.findall(text or ''):
        addr = addr.lower()
        if role_of(addr) != 'personal':
            continue                       # info@/security@/… are not people
        local, _, edom = addr.partition('@')
        on_domain = base and (edom == base or edom.endswith('.' + base))
        name = _name_from_local(local)
        if name and on_domain:
            people.append({'name': name, 'title': '', 'email': addr,
                           'social': []})
    return people


def build_roster(people: List[Dict], domain: str) -> Dict:
    """Dedupe people, infer the on-domain e-mail format, fill in probable
    addresses (pure).

    On-domain = the address domain equals ``domain`` or is a subdomain of it."""
    base = (domain or '').lower().lstrip('.')

    def is_on_domain(addr: str) -> bool:
        edom = addr.split('@', 1)[1] if '@' in addr else ''
        return bool(base) and (edom == base or edom.endswith('.' + base))

    # Merge by normalized name; a record with a real email/title wins.
    merged: Dict[str, Dict] = {}
    for p in people:
        first, last = _split_name(p.get('name', ''))
        if not first:
            continue
        key = f'{first} {last}'.strip()
        cur = merged.setdefault(key, {'name': p['name'].strip(), 'title': '',
                                      'email': '', 'social': []})
        if p.get('title') and not cur['title']:
            cur['title'] = p['title']
        if p.get('email') and not cur['email']:
            cur['email'] = p['email']
        for s in p.get('social', []):
            if s not in cur['social']:
                cur['social'].append(s)

    # Infer the org's format from name↔local pairs that sit on the domain.
    pairs: List[Tuple[str, str, str]] = []
    for rec in merged.values():
        if rec['email'] and is_on_domain(rec['email']):
            first, last = _split_name(rec['name'])
            pairs.append((first, last, rec['email'].split('@', 1)[0]))
    fmt = infer_format(pairs)

    roster: List[Dict] = []
    for key in sorted(merged):
        rec = merged[key]
        if rec['email']:
            source = 'found'
        else:
            guess = generate_email(rec['name'], fmt, base)
            rec['email'] = guess or ''
            source = 'inferred' if guess else ''
        roster.append({**rec, 'email_source': source})

    with_email = sum(1 for r in roster if r['email'])
    return {'total': len(roster), 'with_email': with_email, 'format': fmt,
            'people': roster}


# ── discovery (fetch + extract + roster) ──────────────────────────────────────

def discover(target: str, fetch: Optional[Callable] = None,
             timeout: float = _FETCH_TIMEOUT,
             profile: str = 'chrome_windows') -> Dict:
    """Harvest a target's people from its homepage and team/about pages.

    ``fetch(url)`` overrides the default getter (tests inject a fake). Returns
    ``{status, domain, sources, ...build_roster}``."""
    root, domain = target_root_and_domain(target)
    getter = fetch or (lambda u: _fetch_text(u, timeout, profile))

    people: List[Dict] = []
    scanned: List[str] = []
    seen = set()
    for path in TEAM_PATHS:
        url = root + path
        if url in seen:
            continue
        seen.add(url)
        text = getter(url)
        if text:
            found = extract_people(text, domain)
            if found:
                scanned.append(path or '/')
                people.extend(found)

    if not people:
        return {'status': 'No employees', 'domain': domain, 'sources': scanned,
                'total': 0, 'with_email': 0, 'format': None, 'people': []}

    roster = build_roster(people, domain)
    roster.update({'status': 'Success', 'domain': domain, 'sources': scanned})
    return roster


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

_SOURCE_LABEL = {'found': 'найден', 'inferred': 'предположит.'}


def render_html(data: Dict) -> str:
    """Render the harvested roster as an offline HTML fragment."""
    e = html.escape
    if not data or data.get('status') != 'Success':
        return '<p style="font-size:13px;color:#999;">Сотрудники не найдены</p>'

    fmt = data.get('format')
    head = (f'<p style="font-size:13px;">Найдено сотрудников: '
            f'<b>{e(str(data.get("total", 0)))}</b> '
            f'(с e-mail: {e(str(data.get("with_email", 0)))}; '
            f'формат: <b>{e(fmt) if fmt else "—"}</b>; '
            f'источники: {e(", ".join(data.get("sources", [])) or "—")})</p>')

    rows = []
    for p in data.get('people', [])[:60]:
        email = p.get('email', '')
        src = p.get('email_source', '')
        email_cell = (f'<span style="font-family:monospace;font-size:12px;">'
                      f'{e(email)}</span>'
                      f' <span style="color:#999;">({e(_SOURCE_LABEL.get(src, src))})</span>'
                      if email else '<span style="color:#bbb;">—</span>')
        title = p.get('title', '')
        rows.append(
            f'<tr><td style="padding:2px 12px 2px 0;"><b style="font-size:12px;">'
            f'{e(p.get("name", ""))}</b>'
            + (f' <span style="color:#666;font-size:11px;">— {e(title)}</span>'
               if title else '')
            + f'</td><td style="font-size:12px;">{email_cell}</td></tr>')
    table = (f'<table style="font-size:13px;border-collapse:collapse;">'
             f'{"".join(rows)}</table>' if rows else '')
    return head + table
