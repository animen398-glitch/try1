"""core/dns_intel.py
DNS Intelligence — the records a domain publishes and what its email-auth posture
says about it (roadmap #13, OSINT).

Resolves A / AAAA / MX / TXT / NS / CAA plus the derived email-auth records
(SPF, DMARC, DKIM) and turns the gaps into findings (no/weak SPF, no/weak DMARC,
missing CAA …) that fold into the unified risk engine.

Why DNS-over-HTTPS: the standard library can resolve A/AAAA (``socket``) but not
MX/TXT/CAA/etc., and pulling in ``dnspython`` would violate the minimal-deps
invariant (I1). A DoH JSON resolver (Google's ``/resolve``) gives every record
type over plain ``urllib`` + ``json`` — no new dependency.

Invariants:
  * I1 — stdlib only (json + urllib via SessionBuilder).
  * I5 — the network query (``_doh_query``) is separated from the pure analysis
    (``analyze``) and injectable into ``discover``, so tests never hit the
    network.
"""

import html
import json
from typing import Callable, Dict, List, Optional
from urllib.parse import quote, urlparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

DOH_URL = 'https://dns.google/resolve'
_FETCH_TIMEOUT = 10.0

# Record types resolved directly on the apex domain.
RECORD_TYPES = ('A', 'AAAA', 'MX', 'TXT', 'NS', 'CAA')

# DKIM has no fixed location — the selector is chosen by the sender. Probe the
# selectors used by the common mail providers / tooling.
DKIM_SELECTORS = ('default', 'google', 'selector1', 'selector2', 'k1', 'k2',
                  'dkim', 'mail', 'smtp', 's1', 's2')


# ── network (injectable; kept out of the pure analyzer) ───────────────────────

def _doh_query(name: str, rtype: str, timeout: float = _FETCH_TIMEOUT,
               profile: str = 'chrome_windows') -> List[str]:
    """Resolve ``name``/``rtype`` over DoH and return the answer ``data`` values.

    Returns [] on any failure or NXDOMAIN — the caller treats absence as
    "record not published"."""
    url = f'{DOH_URL}?name={quote(name)}&type={quote(rtype)}'
    try:
        req = SessionBuilder(profile).make_request(url)
        req.add_header('Accept', 'application/dns-json')
        text = urlopen_text(req, timeout, attempts=2)
        data = json.loads(text)
    except Exception:
        return []
    answers = data.get('Answer') if isinstance(data, dict) else None
    if not isinstance(answers, list):
        return []
    out: List[str] = []
    for a in answers:
        if isinstance(a, dict) and a.get('data'):
            # TXT data comes wrapped in quotes; normalize for downstream parsing.
            out.append(str(a['data']).strip().strip('"'))
    return out


def fetch_records(domain: str, query: Optional[Callable] = None) -> Dict:
    """Resolve every record type (+ DMARC and DKIM selectors) for ``domain``.

    ``query(name, rtype)`` does one DoH lookup (injected in tests). Returns a
    dict ``{A, AAAA, MX, TXT, NS, CAA, DMARC, DKIM}`` where DKIM maps selector
    -> records."""
    q = query or (lambda name, rtype: _doh_query(name, rtype))
    records: Dict = {rtype: q(domain, rtype) for rtype in RECORD_TYPES}
    records['DMARC'] = q(f'_dmarc.{domain}', 'TXT')
    dkim: Dict[str, List[str]] = {}
    for sel in DKIM_SELECTORS:
        ans = q(f'{sel}._domainkey.{domain}', 'TXT')
        if ans:
            dkim[sel] = ans
    records['DKIM'] = dkim
    return records


# ── pure analysis ─────────────────────────────────────────────────────────────

def _spf(records: Dict) -> Optional[str]:
    for txt in records.get('TXT', []):
        if txt.lower().startswith('v=spf1'):
            return txt
    return None


def _spf_all_qualifier(spf: Optional[str]) -> Optional[str]:
    """The qualifier on the SPF ``all`` mechanism: ``-`` (hardfail / strong),
    ``~`` (softfail), ``?`` (neutral) or ``+`` (pass-all / weak). ``None`` when the
    record has no ``all`` mechanism. A bare ``all`` defaults to ``+`` per RFC 7208."""
    if not spf:
        return None
    for tok in str(spf).split():
        t = tok.strip().lower()
        if t == 'all':
            return '+'
        if len(t) == 4 and t[1:] == 'all' and t[0] in '+-~?':
            return t[0]
    return None


def _dmarc_policy(records: Dict) -> Optional[str]:
    """The DMARC policy (``none``/``quarantine``/``reject``) or None if absent."""
    for txt in records.get('DMARC', []):
        if txt.lower().startswith('v=dmarc1'):
            for part in txt.split(';'):
                part = part.strip()
                if part.lower().startswith('p='):
                    return part[2:].strip().lower()
            return 'none'   # DMARC present but no explicit policy tag
    return None


def analyze(records: Dict) -> Dict:
    """Derive email-auth posture + findings from resolved records (pure)."""
    spf = _spf(records)
    dmarc = _dmarc_policy(records)
    dkim_selectors = sorted((records.get('DKIM') or {}).keys())
    has_caa = bool(records.get('CAA'))

    findings: List[Dict] = []

    def add(sev: str, title: str, detail: str = ''):
        findings.append({'severity': sev, 'title': title, 'detail': detail,
                         'source': 'dns'})

    if not spf:
        add('Medium', 'No SPF record',
            'Domain publishes no SPF (v=spf1) TXT record — sender spoofing is easier.')
    else:
        # A present SPF can still be weak: its ``all`` qualifier decides enforcement.
        # ``~all`` (softfail) is the widely-accepted standard (Google/Microsoft use
        # it), so it is not flagged; only the genuinely broken qualifiers are.
        qual = _spf_all_qualifier(spf)
        if qual == '+':
            add('Medium', 'SPF allows all senders (+all)',
                'SPF ends in +all (or a bare all) — every sender passes SPF, '
                'defeating its purpose and authorizing spoofed mail.')
        elif qual == '?':
            add('Info', 'SPF policy is neutral (?all)',
                'SPF ends in ?all (neutral) — it makes no assertion about senders '
                'not listed in the record.')
    if dmarc is None:
        add('Medium', 'No DMARC record',
            'No _dmarc TXT record — recipients have no policy to act on failures.')
    elif dmarc == 'none':
        add('Info', 'DMARC policy is p=none',
            'DMARC is monitor-only (p=none); failing mail is still delivered.')
    if not dkim_selectors:
        add('Info', 'No DKIM selector found',
            'None of the common DKIM selectors resolved (mail may still sign with a custom selector).')
    if not has_caa:
        add('Info', 'No CAA record',
            'No CAA record — any certificate authority may issue certs for this domain.')

    return {
        'email_auth': {
            'spf': spf,
            'dmarc': dmarc,
            'dkim_selectors': dkim_selectors,
            'caa': has_caa,
        },
        'findings': findings,
    }


# ── discovery (resolve + analyze) ─────────────────────────────────────────────

def discover(target: str, query: Optional[Callable] = None,
             timeout: float = _FETCH_TIMEOUT,
             profile: str = 'chrome_windows') -> Dict:
    """Resolve a target's DNS records and analyze its email-auth posture.

    ``query(name, rtype)`` overrides the default DoH lookup (tests inject a
    fake). Returns ``{status, domain, records, email_auth, findings}``."""
    domain = urlparse(target if '://' in target else 'https://' + target).netloc \
        or target
    domain = domain.split(':')[0]
    q = query or (lambda name, rtype: _doh_query(name, rtype, timeout, profile))
    records = fetch_records(domain, query=q)

    has_any = any(records.get(t) for t in RECORD_TYPES) or records.get('DKIM')
    if not has_any:
        return {'status': 'No records', 'domain': domain, 'records': records,
                'email_auth': {}, 'findings': []}

    analysis = analyze(records)
    return {'status': 'Success', 'domain': domain, 'records': records,
            **analysis}


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

def render_html(data: Dict) -> str:
    """Render the DNS summary as an offline HTML fragment."""
    e = html.escape
    if not data or data.get('status') != 'Success':
        return '<p style="font-size:13px;color:#999;">DNS-записи не найдены</p>'

    records = data.get('records', {})
    rows = []
    for rtype in RECORD_TYPES:
        vals = records.get(rtype) or []
        if vals:
            rows.append(
                f'<tr><td style="color:#666;padding:2px 12px 2px 0;vertical-align:top;">'
                f'{e(rtype)}</td><td style="font-family:monospace;font-size:12px;'
                f'word-break:break-all;">{e("; ".join(vals[:8]))}</td></tr>')
    table = (f'<table style="font-size:13px;">{"".join(rows)}</table>'
             if rows else '')

    ea = data.get('email_auth', {})
    dkim = ', '.join(ea.get('dkim_selectors') or []) or '—'
    auth = (f'<p style="font-size:13px;margin-top:8px;">'
            f'SPF: <b>{"да" if ea.get("spf") else "нет"}</b> · '
            f'DMARC: <b>{e(str(ea.get("dmarc") or "нет"))}</b> · '
            f'DKIM: <b>{e(dkim)}</b> · '
            f'CAA: <b>{"да" if ea.get("caa") else "нет"}</b></p>')

    findings = data.get('findings') or []
    fitems = ''.join(
        f'<li style="margin:1px 0;"><b>[{e(f.get("severity", ""))}]</b> '
        f'{e(f.get("title", ""))}</li>' for f in findings)
    flist = (f'<ul style="font-size:12px;color:#444;margin:6px 0;">{fitems}</ul>'
             if fitems else '')
    return table + auth + flist
