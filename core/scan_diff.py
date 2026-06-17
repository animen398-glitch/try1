"""core/scan_diff.py
Scan Diff — what changed on a target between two Full Collection scans.

A project (core/project.py) keeps every scan's full ``report.json`` under
``scans/<id>/``. ``diff(report_a, report_b)`` is a pure, deterministic
function over two such report dicts: it never touches the network or the
filesystem (architectural invariants I1/I2/I5), so the GUI stays a thin
caller (I4) and tests run on synthetic reports.

Comparison honesty: a section is only compared when its source phase ran
successfully in BOTH scans — otherwise it goes to ``skipped`` with a reason.
A phase that failed (or didn't run) in one scan must not masquerade as
"everything was removed".

Secret values are masked at diff-build time, so the diff dict itself — and
anything rendered or serialized from it — never carries a full leaked key.
"""

import html
from typing import Dict, List, Optional

from core.executive_summary import RISK_COLORS, cert_expiry_status, parse_cert_date

# Section -> the phase whose success it depends on (single place to extend
# when the collection pipeline gains new phases, e.g. subdomains).
SECTION_PHASES = {
    'pages':        'capture',
    'subdomains':   'subdomains',
    'secrets':      'api',
    'technologies': 'recon',
    'dependencies': 'recon',
    'headers':      'recon',
    'cookies':      'cookies',
    'certificates': 'certificate',
    'endpoints':    'katana',
    'apis':         'openapi',
    'historical':   'historical',
    'dns':          'dns',
    'emails':       'emails',
    'employees':    'employees',
    'ct':           'ct',
    'graphql':      'security',
    'sourcemap':    'security',
    'findings':     'vulns',
}
SECTION_TITLES = {
    'pages':        'Страницы (Site Map)',
    'subdomains':   'Субдомены',
    'secrets':      'Секреты / ключи',
    'technologies': 'Технологии',
    'dependencies': 'Зависимости (JS)',
    'headers':      'HTTP-заголовки',
    'cookies':      'Cookies',
    'certificates': 'TLS-сертификат',
    'endpoints':    'Эндпоинты (Katana)',
    'apis':         'API (OpenAPI)',
    'historical':   'Историч. URL (интересные)',
    'dns':          'DNS / email-auth',
    'emails':       'E-mail адреса',
    'employees':    'Сотрудники',
    'ct':           'CT-сертификаты',
    'graphql':      'GraphQL',
    'sourcemap':    'Source maps (исходники)',
    'findings':     'Findings',
}


# ── helpers ──────────────────────────────────────────────────────────────────

def _phase(report: Dict, name: str) -> Optional[Dict]:
    phase = (report or {}).get('phases', {}).get(name)
    return phase if isinstance(phase, dict) else None


def _phase_ok(report: Dict, name: str) -> bool:
    phase = _phase(report, name)
    return bool(phase) and phase.get('status') == 'Success'


def _data(report: Dict, name: str) -> Dict:
    phase = _phase(report, name) or {}
    data = phase.get('data', {})
    return data if isinstance(data, dict) else {}


def _mask(value: str) -> str:
    """Redact a secret value: keep a short identifying prefix only."""
    s = str(value)
    keep = 6 if len(s) > 8 else 2
    return f'{s[:keep]}…({len(s)})'


# ── per-section extractors (report -> comparable mapping, or None) ───────────
# Each returns ``None`` when the data shape it needs is absent (e.g. a legacy
# scan that predates the field) — the section is then skipped, not fabricated.

def _extract_pages(report: Dict) -> Optional[Dict]:
    site_map = _data(report, 'capture').get('site_map')
    if not isinstance(site_map, list):
        return None
    return {e.get('url'): {'status': e.get('status'),
                           'type': e.get('content_type')}
            for e in site_map if isinstance(e, dict) and e.get('url')}


def _extract_subdomains(report: Dict) -> Optional[Dict]:
    results = _data(report, 'subdomains').get('results')
    if not isinstance(results, list):
        return None
    out: Dict[str, str] = {}
    for e in results:
        if isinstance(e, dict) and e.get('subdomain'):
            host = str(e['subdomain'])
            # Flag takeover candidates in the displayed label.
            out[host] = f'{host} ⚠ takeover' if e.get('takeover') else host
    return out


def _extract_secrets(report: Dict) -> Optional[Dict]:
    details = _data(report, 'api').get('details')
    if not isinstance(details, dict):
        return None
    out = {}
    for key_type, values in details.items():
        for v in (values if isinstance(values, list) else [values]):
            # Compare on the real value; expose only the masked form.
            out[(str(key_type), str(v))] = f'{key_type}: {_mask(v)}'
    return out


def _extract_technologies(report: Dict) -> Optional[Dict]:
    rd = _data(report, 'recon')
    techs = rd.get('technologies')
    cms = rd.get('cms')
    if not isinstance(techs, list) and not isinstance(cms, list):
        return None
    out: Dict[str, Dict] = {}
    for name in (cms if isinstance(cms, list) else []):
        out[str(name)] = {'category': 'CMS', 'version': None}
    for t in (techs if isinstance(techs, list) else []):
        if isinstance(t, dict) and t.get('name'):
            out[str(t['name'])] = {'category': t.get('category'),
                                   'version': t.get('version')}
    return out


def _extract_dependencies(report: Dict) -> Optional[Dict]:
    deps = _data(report, 'recon').get('dependencies')
    libs = deps.get('libraries') if isinstance(deps, dict) else None
    if not isinstance(libs, list):
        return None
    return {str(d['name']): {'version': d.get('version'),
                             'vulnerable': bool(d.get('vulnerabilities'))}
            for d in libs if isinstance(d, dict) and d.get('name')}


def _extract_headers(report: Dict) -> Optional[Dict]:
    rd = _data(report, 'recon')
    server = rd.get('server_headers')
    security = rd.get('security_headers')
    if not isinstance(server, dict) and not isinstance(security, dict):
        return None
    merged: Dict[str, str] = {}
    for src in (server, security):
        if isinstance(src, dict):
            merged.update({str(k): str(v) for k, v in src.items()
                           if v not in (None, '')})
    return merged


def _extract_certificate(report: Dict) -> Optional[Dict]:
    # The certificate phase stores the flat cert summary as its ``data``.
    data = _data(report, 'certificate')
    fields = {k: str(v) for k, v in data.items() if v not in (None, '')}
    # Synthetic expiry status, judged against *this scan's* timestamp so a
    # historical diff sees the transition into expired/expiring as a changed
    # field (not against today). The risk engine shares the same classifier.
    status = cert_expiry_status(data.get('not_after'),
                                parse_cert_date(report.get('started_at')))
    if status:
        fields['expiry'] = status
    return fields or None


def _extract_endpoints(report: Dict) -> Optional[Dict]:
    endpoints = _data(report, 'katana').get('endpoints')
    if not isinstance(endpoints, list):
        return None
    return {str(u): str(u) for u in endpoints}


def _extract_openapi(report: Dict) -> Optional[Dict]:
    endpoints = _data(report, 'openapi').get('endpoints')
    if not isinstance(endpoints, list):
        return None
    out: Dict[str, str] = {}
    for e in endpoints:
        if isinstance(e, dict) and e.get('path'):
            key = f"{e.get('method', '')} {e['path']}".strip()
            out[key] = key
    return out


def _extract_historical(report: Dict) -> Optional[Dict]:
    # Diff the security-relevant subset (admin/auth/api/config), not the whole
    # archive — a newly-archived admin/config URL is the signal worth surfacing.
    interesting = _data(report, 'historical').get('interesting')
    if not isinstance(interesting, list):
        return None
    return {str(u): str(u) for u in interesting}


def _extract_dns(report: Dict) -> Optional[Dict]:
    # Compare the email-auth posture field-by-field (like headers): a newly
    # added SPF, a DMARC policy change, etc.
    ea = _data(report, 'dns').get('email_auth')
    if not isinstance(ea, dict):
        return None
    return {
        'SPF': ea.get('spf') or '—',
        'DMARC': ea.get('dmarc') or '—',
        'DKIM': ','.join(ea.get('dkim_selectors') or []) or '—',
        'CAA': 'yes' if ea.get('caa') else 'no',
    }


def _extract_emails(report: Dict) -> Optional[Dict]:
    data = _data(report, 'emails')
    if 'on_domain' not in data and 'external' not in data:
        return None
    addrs = (data.get('on_domain') or []) + (data.get('external') or [])
    return {str(a): str(a) for a in addrs}


def _extract_employees(report: Dict) -> Optional[Dict]:
    people = _data(report, 'employees').get('people')
    if not isinstance(people, list):
        return None
    out: Dict[str, str] = {}
    for p in people:
        if isinstance(p, dict) and p.get('name'):
            name = str(p['name'])
            title = str(p.get('title') or '')
            out[name] = f'{name} — {title}' if title else name
    return out


def _extract_ct(report: Dict) -> Optional[Dict]:
    # A newly logged certificate (by crt.sh id) is the signal worth surfacing
    # between scans — labelled by issue date, CA and the names it covers.
    certs = _data(report, 'ct').get('certs')
    if not isinstance(certs, list):
        return None
    out: Dict[str, str] = {}
    for c in certs:
        if isinstance(c, dict) and c.get('id') is not None:
            date = str(c.get('not_before') or '')[:10] or '?'
            issuer = str(c.get('issuer') or '')
            names = ', '.join(c.get('names') or [])
            out[str(c['id'])] = f'{date} · {issuer}: {names}'.strip(' :')
    return out


def _extract_graphql(report: Dict) -> Optional[Dict]:
    # The Security Audit probes conventional GraphQL endpoints and flags open
    # introspection. Diff per-endpoint with its introspection state as the value,
    # so a schema that turns from closed to OPEN (the highest-value GraphQL
    # signal) surfaces as a *changed* row, not just a silent re-discovery.
    eps = _data(report, 'security').get('graphql')
    if not isinstance(eps, list):
        return None
    out: Dict[str, str] = {}
    for g in eps:
        if isinstance(g, dict) and g.get('url'):
            out[str(g['url'])] = ('introspection on' if g.get('introspection')
                                  else 'reachable')
    return out


def _extract_sourcemap(report: Dict) -> Optional[Dict]:
    # The Security Audit fetches served .map files; one that leaks the original
    # source (has_content) is the risk-bearing subset. Surface those by URL so a
    # newly-served source-code leak appears as an added row between scans (a map
    # that stops leaking just drops out — not an event).
    maps = _data(report, 'security').get('source_maps')
    if not isinstance(maps, list):
        return None
    return {str(m['url']): str(m['url'])
            for m in maps
            if isinstance(m, dict) and m.get('url') and m.get('has_content')}


def _extract_cookies(report: Dict) -> Optional[Dict]:
    # The Cookie Audit scores every Set-Cookie by its security attributes
    # (HttpOnly / Secure / SameSite). Diff per-cookie with its verdict as the
    # value, so a cookie that loses protection (Strong/Moderate → Weak) surfaces
    # as a *changed* row — a regression — not just a silent re-discovery.
    cookies = _data(report, 'cookies').get('cookies')
    if not isinstance(cookies, list):
        return None
    return {str(c['name']): str(c.get('verdict') or '—')
            for c in cookies
            if isinstance(c, dict) and c.get('name')}


def _extract_findings(report: Dict) -> Optional[Dict]:
    phase = _phase(report, 'vulns') or {}
    findings = phase.get('findings')
    if not isinstance(findings, list):
        return None
    return {(f.get('severity', ''), f.get('title', '')):
            f"[{f.get('severity', '')}] {f.get('title', '')}"
            for f in findings if isinstance(f, dict)}


_EXTRACTORS = {
    'pages':        _extract_pages,
    'subdomains':   _extract_subdomains,
    'secrets':      _extract_secrets,
    'technologies': _extract_technologies,
    'dependencies': _extract_dependencies,
    'headers':      _extract_headers,
    'certificates': _extract_certificate,
    'endpoints':    _extract_endpoints,
    'apis':         _extract_openapi,
    'historical':   _extract_historical,
    'dns':          _extract_dns,
    'emails':       _extract_emails,
    'employees':    _extract_employees,
    'ct':           _extract_ct,
    'graphql':      _extract_graphql,
    'sourcemap':    _extract_sourcemap,
    'cookies':      _extract_cookies,
    'findings':     _extract_findings,
}

# Sections whose values are display-only labels: a key either exists or not,
# there is no meaningful "changed" state for it.
_SET_LIKE = {'subdomains', 'secrets', 'endpoints', 'apis', 'historical',
             'emails', 'employees', 'ct', 'sourcemap', 'findings'}


def _label(section: str, key, value) -> str:
    """Human-readable line for an added/removed item."""
    if section in _SET_LIKE:
        return str(value)
    if section == 'pages':
        status = value.get('status')
        return f'{key}' + (f' [{status}]' if status is not None else '')
    if section == 'technologies':
        ver = value.get('version')
        return f'{key}' + (f' {ver}' if ver else '')
    if section == 'dependencies':
        ver = value.get('version')
        flag = ' ⚠ vulnerable' if value.get('vulnerable') else ''
        return f'{key}' + (f' {ver}' if ver else '') + flag
    if section in ('headers', 'certificates', 'dns', 'graphql', 'cookies'):
        return f'{key}: {value}'
    return str(key)


def _changed_entry(section: str, key, a, b) -> Optional[Dict]:
    """A 'changed' record for a key present in both scans, or None if equal."""
    if section in _SET_LIKE or a == b:
        return None
    if section == 'pages':
        fields = [(f'{x.get("status")} ({x.get("type")})'
                   if x.get('type') else str(x.get('status'))) for x in (a, b)]
    elif section == 'technologies':
        fields = [str(x.get('version') or '—') for x in (a, b)]
    elif section == 'dependencies':
        fields = [(str(x.get('version') or '—')
                   + (' ⚠' if x.get('vulnerable') else '')) for x in (a, b)]
    else:   # headers
        fields = [str(a), str(b)]
    return {'key': str(key), 'a': fields[0], 'b': fields[1]}


# ── diff ─────────────────────────────────────────────────────────────────────

def _scan_header(report: Dict) -> Dict:
    es = (report or {}).get('executive_summary') or {}
    metrics = es.get('metrics', {}) if isinstance(es, dict) else {}
    return {
        'scan_id': (report or {}).get('scan_id', '?'),
        'finished_at': (report or {}).get('finished_at', ''),
        'risk_level': es.get('risk_level', '—'),
        'risk_100': es.get('risk_100', metrics.get('risk_100', 0)),
    }


def diff(report_a: Dict, report_b: Dict) -> Dict:
    """Structured diff of two collection reports (A = older, B = newer).

    Pure and deterministic; tolerant of missing/failed/legacy phases (they
    land in ``skipped``, never in false added/removed noise).
    """
    a_hdr, b_hdr = _scan_header(report_a), _scan_header(report_b)
    sections: Dict[str, Dict] = {}
    skipped: Dict[str, str] = {}
    summary: Dict[str, Dict] = {}

    for section, phase_name in SECTION_PHASES.items():
        missing = [label for label, rep in (('A', report_a), ('B', report_b))
                   if not _phase_ok(rep, phase_name)]
        if missing:
            skipped[section] = (f'фаза {phase_name} не выполнена в скане '
                                f'{" и ".join(missing)}')
            continue
        map_a = _EXTRACTORS[section](report_a)
        map_b = _EXTRACTORS[section](report_b)
        if map_a is None or map_b is None:
            skipped[section] = f'нет данных {phase_name} (легаси-скан)'
            continue

        added = sorted(_label(section, k, map_b[k])
                       for k in map_b.keys() - map_a.keys())
        removed = sorted(_label(section, k, map_a[k])
                         for k in map_a.keys() - map_b.keys())
        changed: List[Dict] = []
        for k in sorted(map_a.keys() & map_b.keys(), key=str):
            entry = _changed_entry(section, k, map_a[k], map_b[k])
            if entry:
                changed.append(entry)

        sections[section] = {'added': added, 'removed': removed,
                             'changed': changed}
        summary[section] = {'added': len(added), 'removed': len(removed),
                            'changed': len(changed)}

    return {
        'a': a_hdr,
        'b': b_hdr,
        'risk': {
            'level_a': a_hdr['risk_level'], 'level_b': b_hdr['risk_level'],
            'risk_100_a': a_hdr['risk_100'], 'risk_100_b': b_hdr['risk_100'],
        },
        'sections': sections,
        'skipped': skipped,
        'summary': summary,
        'is_empty': not any(any(c.values()) for c in summary.values()),
    }


def summarize_line(d: Dict) -> str:
    """One-line digest for the GUI log/status bar."""
    parts = []
    for section, counts in d.get('summary', {}).items():
        bits = [f'{sign}{counts[key]}'
                for sign, key in (('+', 'added'), ('-', 'removed'),
                                  ('~', 'changed')) if counts.get(key)]
        if bits:
            parts.append(f'{SECTION_TITLES.get(section, section)}: '
                         f'{"/".join(bits)}')
    risk = d.get('risk', {})
    risk_str = (f"риск {risk.get('level_a', '—')} "
                f"{risk.get('risk_100_a', 0)}/100 → "
                f"{risk.get('level_b', '—')} {risk.get('risk_100_b', 0)}/100")
    if not parts:
        return f'Изменений не обнаружено · {risk_str}'
    return ' · '.join(parts + [risk_str])


# ── change events (shared by Alert Center #9 and Timeline #F2) ─────────────────
# One classifier turns a diff into typed events so the two consumers never
# diverge: Alert Center keeps the alertable subset (alerts.ALERT_TYPES), the
# Timeline takes them all. Each event is {type, title, severity, section}.
EVENT_SEVERITY = {
    'new_secret':          'high',
    'takeover':            'critical',
    'new_subdomain':       'medium',
    'new_technology':      'info',
    'tech_version_change': 'info',
    'cert_change':         'medium',
    'cert_expiring':       'medium',
    'cert_expired':        'high',
    'new_endpoint':        'info',
    'new_graphql':         'medium',
    'graphql_introspection': 'high',
    'new_sourcemap':       'high',
    'weak_cookie':         'medium',
    'cookie_weakened':     'high',
    'new_vulnerable_dependency': 'high',
    'dependency_vulnerable':     'high',
    'risk_increase':       'high',
    'risk_decrease':       'info',
}


def diff_events(d: Dict) -> List[Dict]:
    """All change events from a ``diff`` dict (pure, no I/O).

    Superset of the alertable events (alerts filter by ``ALERT_TYPES``); the
    timeline consumes the full set. Secret titles are already masked in the diff.
    """
    sections = (d or {}).get('sections', {})
    out: List[Dict] = []

    def add(type_: str, title, section: str) -> None:
        out.append({'type': type_, 'title': str(title),
                    'severity': EVENT_SEVERITY[type_], 'section': section})

    for label in sections.get('secrets', {}).get('added', []):
        add('new_secret', label, 'secrets')

    # Subdomains: a takeover candidate is the dangerous subset (its label carries
    # the marker core.scan_diff attaches).
    for label in sections.get('subdomains', {}).get('added', []):
        text = str(label)
        add('takeover' if 'takeover' in text.lower() else 'new_subdomain',
            text, 'subdomains')

    for label in sections.get('technologies', {}).get('added', []):
        add('new_technology', label, 'technologies')
    for ch in sections.get('technologies', {}).get('changed', []):
        if isinstance(ch, dict):
            add('tech_version_change',
                f"{ch.get('key')}: {ch.get('a')} → {ch.get('b')}", 'technologies')

    # Certificates: a renewed/changed field is a generic cert_change, but the
    # synthetic ``expiry`` status carries the semantic signal — a cert that has
    # crossed into expired (high) or expiring-soon (medium). Fire on both a
    # newly-tracked cert that is already past/near its deadline and a
    # valid→expiring→expired transition. A renewal (→ valid) is not an event.
    cert = sections.get('certificates', {})
    for label in cert.get('added', []):
        text = str(label)
        if text.startswith('expiry: expired'):
            add('cert_expired', 'сертификат истёк', 'certificates')
        elif text.startswith('expiry: expiring'):
            add('cert_expiring', 'сертификат скоро истечёт', 'certificates')
    for ch in cert.get('changed', []):
        if not isinstance(ch, dict):
            continue
        if ch.get('key') == 'expiry':
            b = str(ch.get('b', ''))
            if b == 'expired':
                add('cert_expired',
                    f"сертификат истёк ({ch.get('a')} → {b})", 'certificates')
            elif b == 'expiring':
                add('cert_expiring',
                    f"сертификат скоро истечёт ({ch.get('a')} → {b})", 'certificates')
        else:
            add('cert_change',
                f"{ch.get('key')}: {ch.get('a')} → {ch.get('b')}", 'certificates')

    # A newly discovered endpoint (Katana crawl or OpenAPI spec).
    for section in ('endpoints', 'apis'):
        for label in sections.get(section, {}).get('added', []):
            add('new_endpoint', label, section)

    # GraphQL: a newly reachable endpoint is attack surface; one whose schema is
    # now open to introspection is the high-value signal (matches the risk engine,
    # which forces ≥High on open introspection). Fire on both an added endpoint
    # that already exposes introspection and a reachable→open transition.
    for label in sections.get('graphql', {}).get('added', []):
        text = str(label)
        add('graphql_introspection' if 'introspection on' in text
            else 'new_graphql', text, 'graphql')
    for ch in sections.get('graphql', {}).get('changed', []):
        if isinstance(ch, dict) and 'introspection on' in str(ch.get('b', '')):
            add('graphql_introspection',
                f"{ch.get('key')}: {ch.get('a')} → {ch.get('b')}", 'graphql')

    # A source map that newly leaks the original source code (Security Audit) is a
    # regression worth alerting — high-value, like an opened GraphQL schema.
    for label in sections.get('sourcemap', {}).get('added', []):
        add('new_sourcemap', label, 'sourcemap')

    # Cookie security posture (Cookie Audit): a newly-served Weak cookie is a
    # surface-discovery note (timeline-only, like new_graphql); an existing
    # cookie that *degraded* to Weak (lost Secure/HttpOnly/SameSite) is a
    # regression worth a push, like an opened GraphQL schema.
    for label in sections.get('cookies', {}).get('added', []):
        if str(label).endswith(': Weak'):
            add('weak_cookie', label, 'cookies')
    for ch in sections.get('cookies', {}).get('changed', []):
        if isinstance(ch, dict) and str(ch.get('b')) == 'Weak':
            add('cookie_weakened',
                f"{ch.get('key')}: {ch.get('a')} → {ch.get('b')}", 'cookies')

    # Dependencies (JS library inventory + CVE audit): a vulnerable library that
    # newly appears, or an existing one that turned vulnerable (a new CVE matched
    # its version, or it was bumped to a vulnerable release), is a clear new risk
    # — alertable, like a newly-leaking source map. The diff already flags
    # vulnerable entries with ⚠ in their label (added) / fields (changed).
    for label in sections.get('dependencies', {}).get('added', []):
        if str(label).endswith(' ⚠ vulnerable'):
            add('new_vulnerable_dependency', label, 'dependencies')
    for ch in sections.get('dependencies', {}).get('changed', []):
        if (isinstance(ch, dict) and '⚠' in str(ch.get('b'))
                and '⚠' not in str(ch.get('a'))):
            add('dependency_vulnerable',
                f"{ch.get('key')}: {ch.get('a')} → {ch.get('b')}", 'dependencies')

    risk = (d or {}).get('risk', {})
    if (risk.get('risk_100_b') or 0) > (risk.get('risk_100_a') or 0):
        add('risk_increase',
            f"{risk.get('level_a')} {risk.get('risk_100_a')} → "
            f"{risk.get('level_b')} {risk.get('risk_100_b')}", 'risk')
    elif (risk.get('risk_100_b') or 0) < (risk.get('risk_100_a') or 0):
        add('risk_decrease',
            f"{risk.get('level_a')} {risk.get('risk_100_a')} → "
            f"{risk.get('level_b')} {risk.get('risk_100_b')}", 'risk')

    return out


def write_diff_report(project, id_a: str, id_b: str) -> Dict:
    """Load two of a project's scans, diff them and write the offline HTML
    into the project's ``reports/`` folder (its first real tenant).

    Returns ``{'diff', 'html_path', 'line'}``. Raises ``ValueError`` when a
    scan's report is missing/corrupt — the caller shows the message as-is.
    Disk-only (no network); called from a GUI worker so the UI stays thin (I4).
    """
    report_a = project.load_scan_report(id_a)
    report_b = project.load_scan_report(id_b)
    for scan_id, rep in ((id_a, report_a), (id_b, report_b)):
        if rep is None:
            raise ValueError(f'Скан {scan_id}: report.json не найден или битый')
    # The report carries its own scan_id, but trust the directory name the
    # user picked (legacy reports may predate the field).
    report_a.setdefault('scan_id', id_a)
    report_b.setdefault('scan_id', id_b)

    d = diff(report_a, report_b)
    out_dir = project.root / 'reports'
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f'diff_{id_a}_vs_{id_b}.html'
    html_path.write_text(render_html(d), encoding='utf-8')
    return {'diff': d, 'html_path': str(html_path), 'line': summarize_line(d)}


# ── offline HTML report ──────────────────────────────────────────────────────

def render_html(d: Dict) -> str:
    """Self-contained offline diff page: inline CSS, no JS, no external
    resources (invariant I2) — same contract as every other report."""
    e = html.escape
    a, b = d.get('a', {}), d.get('b', {})
    risk = d.get('risk', {})

    def risk_chip(level, score) -> str:
        color = RISK_COLORS.get(level, '#555')
        return (f'<span style="background:{color};color:#fff;border-radius:4px;'
                f'padding:2px 8px;font-weight:bold;">{e(str(level))} · '
                f'{e(str(score))}/100</span>')

    banner = (
        f'<div style="border:1px solid #ddd;border-radius:6px;'
        f'padding:12px 16px;margin:8px 0;font-size:14px;">'
        f'Риск: {risk_chip(risk.get("level_a"), risk.get("risk_100_a", 0))}'
        f' <span style="color:#888;">→</span> '
        f'{risk_chip(risk.get("level_b"), risk.get("risk_100_b", 0))}</div>'
    )

    def items(lines, color, sign) -> str:
        return ''.join(
            f'<li style="margin:2px 0;color:{color};">{sign} {e(str(l))}</li>'
            for l in lines)

    cards = []
    for section in SECTION_PHASES:
        if section in d.get('skipped', {}):
            cards.append(
                f'<section style="border:1px solid #eee;border-radius:6px;'
                f'margin:10px 0;padding:10px 16px;color:#999;font-size:13px;">'
                f'<b>{e(SECTION_TITLES[section])}</b> — пропущено: '
                f'{e(d["skipped"][section])}</section>')
            continue
        sec = d.get('sections', {}).get(section)
        if sec is None:
            continue
        changed_lines = [f'{c["key"]}: {c["a"]} → {c["b"]}'
                         for c in sec.get('changed', [])]
        body = (items(sec.get('added', []), '#2e7d32', '+')
                + items(sec.get('removed', []), '#c62828', '−')
                + items(changed_lines, '#b07d00', '~'))
        if not body:
            body = '<li style="color:#999;">без изменений</li>'
        counts = d.get('summary', {}).get(section, {})
        badge = ' / '.join(f'{k} {v}' for k, v in counts.items() if v) or '—'
        cards.append(
            f'<section style="border:1px solid #ddd;border-radius:6px;'
            f'margin:10px 0;padding:10px 16px;">'
            f'<h2 style="margin:0 0 6px;font-size:15px;">'
            f'{e(SECTION_TITLES[section])} '
            f'<span style="color:#888;font-size:12px;">[{e(badge)}]</span></h2>'
            f'<ul style="font-size:13px;margin:4px 0;padding-left:18px;'
            f'list-style:none;max-height:320px;overflow:auto;">{body}</ul>'
            f'</section>')

    empty_note = ('<p style="color:#2e7d32;font-size:14px;">Изменений между '
                  'сканами не обнаружено.</p>' if d.get('is_empty') else '')

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Scan Diff — {e(str(a.get('scan_id', '')))} → {e(str(b.get('scan_id', '')))}</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;
max-width:860px;margin:24px auto;padding:0 16px;color:#222;">
<h1 style="font-size:20px;margin-bottom:4px;">Scan Diff</h1>
<p style="color:#666;font-size:13px;margin-top:0;">
  Скан A: <b>{e(str(a.get('scan_id', '')))}</b> ({e(str(a.get('finished_at', '')))}) →
  Скан B: <b>{e(str(b.get('scan_id', '')))}</b> ({e(str(b.get('finished_at', '')))})
</p>
{banner}
{empty_note}
{''.join(cards)}
<p style="color:#aaa;font-size:11px;margin-top:24px;">
  Advanced Site Analyzer · Scan Diff
</p>
</body></html>"""
