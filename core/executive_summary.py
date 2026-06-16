"""core/executive_summary.py
Deterministic, offline executive summary over a Full Collection report.

Given the aggregated ``report`` dict that ``CollectionRunner`` builds (its
``phases`` — recon / api / capture / cookies / vulns …), this derives a single
risk verdict, the key findings and concrete recommendations — entirely from
data the pipeline already produced. No model, no network, no new dependency
(architectural invariants I1/I2/I5): the same inputs always yield the same
summary, so it is trivially unit-testable.

This is the deterministic core of the "AI Executive Summary" candidate minus
the LLM — it covers the bulk of the value (risk overview + recommendations)
without the nondeterminism or runtime surface of a local model.
"""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Risk verdict -> banner colour (shared palette with the vuln/site-map reports).
RISK_COLORS = {
    'Critical': '#b71c1c',
    'High':     '#c62828',
    'Medium':   '#f9a825',
    'Low':      '#2e7d32',
    'Clean':    '#2e7d32',
}
RISK_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Clean']


def _phase_data(report: Dict, name: str) -> Dict:
    phase = report.get('phases', {}).get(name, {})
    data = phase.get('data', {}) if isinstance(phase, dict) else {}
    return data if isinstance(data, dict) else {}


def _int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _risk_level(score: int, high: int, secrets: int, takeovers: int = 0,
                graphql_introspection: int = 0) -> str:
    """Map weighted signals to a verdict. Thresholds are intentionally simple
    and fixed so the verdict is reproducible and easy to reason about. Leaked
    secrets and subdomain takeovers are both clear-cut Critical signals; an open
    GraphQL schema (introspection) is a clear-cut High signal."""
    if secrets > 0 or takeovers > 0 or high >= 3 or score >= 20:
        return 'Critical'
    if high >= 1 or graphql_introspection > 0 or score >= 10:
        return 'High'
    if score >= 4:
        return 'Medium'
    if score >= 1:
        return 'Low'
    return 'Clean'


# A raw weighted score of 25 already means a serious, Critical-grade target, so
# the 0–100 scale saturates there (×4). The normalised score is the platform's
# single headline risk number; the raw score stays for weighting/sorting.
_SCORE_TO_100 = 4
_SCORE_100_CEILING = 100

# Per-signal weights for the explainable risk score (F-R): each contributing
# signal's points are ``count × weight``, summed into the raw score. Kept as one
# table so the model is transparent and easy to tune. Vulnerabilities are weighed
# by the VulnScanner's own risk_score (already weighted), so they have no entry
# here. Secrets/source-maps weigh heaviest after a takeover (the single worst hop).
RISK_WEIGHTS = {
    'secrets': 5,
    'takeovers': 8,
    'source_map_leaks': 5,
    'weak_cookies': 2,
    'graphql_introspection': 4,   # open GraphQL schema leak (F-R2)
    'infra_concentration': 2,     # shared-infra choke point / blast radius (F-R4)
    'sla_breach': 1,              # remediation past its deadline — overdue surcharge (F-R5)
    'cert_expiry': 2,            # served TLS cert expired / expiring soon (F-R6)
}

# How close to expiry (days) a still-valid leaf cert is flagged as a risk signal.
CERT_EXPIRY_WARN_DAYS = 14


def _risk_factors(vuln_score: int, high: int, medium: int, secrets: int,
                  takeovers: int, source_map_leaks: int, weak_cookies: int,
                  graphql_introspection: int = 0, infra_concentration: int = 0,
                  infra_detail: str = '', sla_breaches: int = 0,
                  sla_detail: str = '', cert_expiry: int = 0,
                  cert_detail: str = '') -> List[Dict]:
    """The explicit, weighted contributions that make up the raw risk score.

    Returns a list of ``{factor, count, weight, points, detail}`` — one per
    *present* signal — so the score is fully explainable ("why is the risk N").
    The sum of ``points`` is the raw score; existing signals keep their exact
    previous weighting, so the number is unchanged from the old flat formula.
    Sorted by points, heaviest first, for display.
    """
    factors: List[Dict] = []
    if vuln_score:
        factors.append({
            'factor': 'Уязвимости (vuln-скан)', 'count': high + medium,
            'weight': None, 'points': vuln_score,
            'detail': f'{high} high · {medium} medium'})

    def add(name: str, count: int, key: str, detail: str = '') -> None:
        if count:
            weight = RISK_WEIGHTS[key]
            factors.append({'factor': name, 'count': count, 'weight': weight,
                            'points': count * weight, 'detail': detail})

    add('Утёкшие секреты', secrets, 'secrets')
    add('Subdomain takeover', takeovers, 'takeovers')
    add('Source map с исходниками', source_map_leaks, 'source_map_leaks')
    add('Слабые cookie', weak_cookies, 'weak_cookies')
    add('GraphQL introspection', graphql_introspection, 'graphql_introspection',
        'открытая схема GraphQL')
    add('Концентрация на инфраструктуре', infra_concentration,
        'infra_concentration', infra_detail)
    add('Просроченная ремедиация (SLA)', sla_breaches, 'sla_breach', sla_detail)
    add('TLS-сертификат истёк/истекает', cert_expiry, 'cert_expiry', cert_detail)
    factors.sort(key=lambda f: f['points'], reverse=True)
    return factors


def _infra_concentration(report: Dict) -> Tuple[int, str]:
    """Shared-infrastructure choke points — the "blast radius" amplifier (F-R4).

    Reads the correlation phase's ``infra_exposure`` (F-K7: findings folded up
    each finding's ip / asn / netblock) and counts the nodes that concentrate
    findings across **≥2 hosts**: those are structural single-points-of-exposure
    — one shared ASN/netblock/IP whose compromise (or whose one fix) touches many
    hosts at once. Pure over ``report['correlation']`` (already derived before the
    summary runs), so the risk math stays a pure function of the report. Returns
    ``(count, detail)`` where ``detail`` names the worst such node."""
    infra = (report.get('correlation') or {}).get('infra_exposure') or []
    concentrated = [n for n in infra
                    if isinstance(n, dict) and _int(n.get('host_count')) >= 2]
    if not concentrated:
        return 0, ''
    worst = concentrated[0]   # infra_exposure is worst-severity-first
    detail = (f"{worst.get('type', '')} {worst.get('node', '')}: "
              f"{_int(worst.get('findings_count'))} находок на "
              f"{_int(worst.get('host_count'))} хостах")
    return len(concentrated), detail


def _sla_breaches(report: Dict) -> Tuple[int, str]:
    """Overdue-remediation amplifier (F-R5).

    Reads the F1 SLA posture the findings sync already stamped onto
    ``report['findings']['sla']`` (DefectDojo-style, reopen-aware deadlines over
    active findings — see ``findings_sla.sla_summary``) and counts findings whose
    remediation window has lapsed. A breach means the team has *known* about a
    finding past its deadline and not closed it — a worse posture signal than a
    fresh finding of the same severity, so it adds a light per-finding surcharge
    on top of the severity weight already counted. Pure over the report (the SLA
    block is computed before the summary runs); ``0`` for any report without a
    synced findings block (older reports / tests). Returns ``(count, detail)``
    where ``detail`` names the worst overdue severity."""
    sla = (report.get('findings') or {}).get('sla') or {}
    breached = _int(sla.get('breached'))
    if breached <= 0:
        return 0, ''
    by_sev = sla.get('by_severity') or {}
    worst = next((sev for sev in ('critical', 'high', 'medium', 'low')
                  if _int((by_sev.get(sev) or {}).get('breached')) > 0), '')
    detail = (f'{breached} находок просрочено'
              + (f', худшая — {worst}' if worst else ''))
    return breached, detail


def parse_cert_date(value) -> Optional[datetime]:
    """Best-effort parse of a certificate validity date into a naive datetime.

    Served-cert ``not_after`` comes in several shapes across the pipeline —
    OpenSSL/RFC ("Aug  1 00:00:00 2026 GMT"), ISO ("2026-09-01" /
    "2026-09-01T00:00:00"), or a bare "%b %d %Y". Tries each, collapsing the
    OpenSSL double-space and dropping a trailing zone; returns ``None`` on
    anything unparseable (degrade-not-raise, F-SR1 ethos). Also parses the ISO
    scan timestamps the report carries (``started_at``), so callers can use it
    as the reference instant."""
    if not value:
        return None
    s = ' '.join(str(value).split())            # collapse OpenSSL double spaces
    try:                                         # ISO (date or datetime)
        return datetime.fromisoformat(s.replace(' ', 'T').rstrip('Z'))
    except ValueError:
        pass
    s2 = s.removesuffix(' GMT').removesuffix(' UTC').strip()
    for fmt in ('%b %d %H:%M:%S %Y', '%b %d %Y', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(s2, fmt)
        except ValueError:
            continue
    return None


def _cert_status_days(not_after, ref: Optional[datetime]) -> Tuple[str, int]:
    """Classify a cert ``not_after`` against ``ref`` (default now).

    Returns ``(status, days_until_expiry)`` where status is
    ``'expired' | 'expiring' | 'valid'`` (or ``''`` for a missing/unparseable
    date); ``days`` is negative once expired. The single source of truth for the
    expiry threshold, shared by the risk amplifier and the Scan-Diff event."""
    expiry = parse_cert_date(not_after)
    if expiry is None:
        return '', 0
    days = (expiry - (ref or datetime.now())).days
    if days < 0:
        return 'expired', days
    if days <= CERT_EXPIRY_WARN_DAYS:
        return 'expiring', days
    return 'valid', days


def cert_expiry_status(not_after, ref: Optional[datetime] = None) -> str:
    """``'expired' | 'expiring' | 'valid' | ''`` for a cert ``not_after``.

    ``ref`` is the reference instant — pass a scan's own timestamp so a
    historical diff judges each scan against when it ran, not against today."""
    return _cert_status_days(not_after, ref)[0]


def _cert_expiry(report: Dict, now: Optional[datetime] = None
                 ) -> Tuple[int, str, bool]:
    """Served-TLS-cert expiry amplifier (F-R6).

    Reads the ``not_after`` of the leaf certificate the (opt-in) ``certificate``
    phase already captured (``cert_info``) and flags a cert that has **expired**
    or is within :data:`CERT_EXPIRY_WARN_DAYS` of expiry. An expired/expiring
    leaf cert is a classic EASM exposure/hygiene signal (broken browser trust,
    imminent outage), so it adds a light per-host amplifier on top of the score.
    Pure derive over the report; ``(0, '', False)`` for a report without a
    certificate phase or an unparseable date. ``now`` is injectable for
    deterministic tests. Returns ``(count, detail, expired)``."""
    status, days = _cert_status_days(
        _phase_data(report, 'certificate').get('not_after'), now)
    if status == 'expired':
        return 1, f'сертификат истёк {abs(days)} дн. назад', True
    if status == 'expiring':
        return 1, f'сертификат истекает через {days} дн.', False
    return 0, '', False


def _count_takeovers(report: Dict) -> int:
    """Subdomain-takeover candidates, if a subdomain phase is present."""
    sub = _phase_data(report, 'subdomains')
    summary = sub.get('summary', {}) if isinstance(sub, dict) else {}
    tc = summary.get('takeover_candidates')
    return len(tc) if isinstance(tc, list) else _int(tc)


def _count_sourcemap_leaks(report: Dict) -> int:
    """Source maps that exposed original source, if a security phase is present."""
    sec = _phase_data(report, 'security')
    summary = sec.get('summary', {}) if isinstance(sec, dict) else {}
    return _int(summary.get('maps_with_content'))


def _graphql_exposure(report: Dict) -> Tuple[int, int]:
    """(reachable GraphQL endpoints, of which expose introspection), if a
    security phase ran. The SecurityAuditor already counts both — surface them
    for the exposure breakdown without re-probing (invariant I3)."""
    sec = _phase_data(report, 'security')
    summary = sec.get('summary', {}) if isinstance(sec, dict) else {}
    return _int(summary.get('graphql')), _int(summary.get('graphql_introspection'))


# Severity → chip colour for the executive headline (light report background).
HEADLINE_COLORS = {
    'critical': '#b71c1c', 'high': '#c62828', 'medium': '#f9a825',
    'low': '#2e7d32', 'info': '#666', 'clean': '#2e7d32',
}


def headline(summary: Dict) -> Dict:
    """The "10-second" executive headline: risk verdict + the most important
    signals as prioritized chips (Cortex-Xpanse-style "show only what matters").

    Pure derive over an executive ``summary``'s ``metrics`` — the chips are the
    same numbers the report/dashboard already carry, surfaced compactly and in
    severity priority (secrets/takeovers first, medium noise last), capped so a
    triager grasps the situation at a glance. Returns
    ``{risk_level, risk_100, chips:[{label, severity}]}``.
    """
    m = summary.get('metrics', {}) if isinstance(summary, dict) else {}
    chips: List[Dict] = []

    def add(label: str, severity: str) -> None:
        chips.append({'label': label, 'severity': severity})

    def _plural(n: int, word: str) -> str:
        return f'{n} {word}' + ('s' if n != 1 else '')

    secrets = _int(m.get('secrets'))
    if secrets:
        add(_plural(secrets, 'Secret'), 'critical')
    takeovers = _int(m.get('takeovers'))
    if takeovers:
        add(_plural(takeovers, 'Takeover'), 'critical')
    source_maps = _int(m.get('source_map_leaks'))
    if source_maps:
        add(_plural(source_maps, 'Source map'), 'critical')
    if _int(m.get('graphql_introspection')):
        add('GraphQL introspection', 'high')
    high = _int(m.get('high'))
    if high:
        add(f'{high} High', 'high')
    weak_cookies = _int(m.get('weak_cookies'))
    if weak_cookies:
        add(_plural(weak_cookies, 'Weak cookie'), 'medium')
    if _int(m.get('graphql')) and not _int(m.get('graphql_introspection')):
        add('GraphQL exposed', 'medium')
    if _int(m.get('cert_expired')):
        add('Cert expired', 'high')
    elif _int(m.get('cert_expiry')):
        add('Cert expiring', 'medium')
    sla_breaches = _int(m.get('sla_breaches'))
    if sla_breaches:
        add(f'{sla_breaches}× SLA overdue', 'high')
    infra_conc = _int(m.get('infra_concentration'))
    if infra_conc:
        add(f'{infra_conc}× shared infra', 'medium')
    medium = _int(m.get('medium'))
    if medium:
        add(f'{medium} Medium', 'medium')

    return {
        'risk_level': summary.get('risk_level', 'Clean'),
        'risk_100': summary.get('risk_100', m.get('risk_100', 0)),
        'chips': chips[:6],   # cap: a headline shows only what matters most
    }


def build_summary(report: Dict) -> Dict:
    """Derive a structured executive summary from a collection ``report``.

    Tolerant of missing/partial phases — every phase is optional, so a report
    that only ran Recon still produces a coherent (low-signal) summary.
    """
    recon = _phase_data(report, 'recon')
    api = _phase_data(report, 'api')
    capture = _phase_data(report, 'capture')
    cookies = _phase_data(report, 'cookies')

    vulns = report.get('phases', {}).get('vulns', {})
    vsum = vulns.get('summary', {}) if isinstance(vulns, dict) else {}
    findings = vulns.get('findings', []) if isinstance(vulns, dict) else []

    # Findings Management (F1): once findings carry a triage status (stamped by
    # FindingsStore.sync), drop the inactive ones (FIXED / IGNORED /
    # FALSE_POSITIVE) from the risk math and re-aggregate — triaging a
    # false-positive lowers the score. The guard keeps behaviour identical for
    # reports/tests without statuses.
    if any(isinstance(f, dict) and f.get('status') for f in findings):
        from core.findings_store import INACTIVE_STATUSES
        from core.vuln_scanner import VulnScanner
        findings = [f for f in findings if not isinstance(f, dict)
                    or f.get('status') not in INACTIVE_STATUSES]
        vsum = VulnScanner.summarize(findings)

    high = _int(vsum.get('high'))
    medium = _int(vsum.get('medium'))
    info = _int(vsum.get('info'))
    vuln_score = _int(vsum.get('risk_score'))
    secrets = _int(api.get('keys_found'))
    weak_cookies = _int(cookies.get('weak'))
    # Unified risk engine: pull every available security signal (Security Audit
    # source maps + subdomain takeovers are zero unless those phases ran).
    source_map_leaks = _count_sourcemap_leaks(report)
    graphql, graphql_introspection = _graphql_exposure(report)
    takeovers = _count_takeovers(report)

    status_summary = capture.get('status_summary', {}) or {}
    non_ok = (_int(status_summary.get('4xx')) + _int(status_summary.get('5xx'))
              + _int(status_summary.get('err')))
    pages = _int(capture.get('pages_captured'))

    # Attack surface breadth (reuses the graph categories) — a separate axis
    # from the risk verdict: how much of the target is exposed/enumerated.
    from core.attack_surface import build_surface, score_band, surface_score
    surface = build_surface(report)
    surface_pts = surface_score(surface)

    # F-R4: shared-infra blast radius as a structural amplifier (0 unless the
    # correlation phase found infra nodes concentrating findings across hosts).
    infra_concentration, infra_detail = _infra_concentration(report)
    # F-R5: overdue-remediation surcharge (0 unless the findings sync stamped a
    # breached SLA onto the report — older reports / tests degrade to zero).
    sla_breaches, sla_detail = _sla_breaches(report)
    # F-R6: served TLS cert expired / expiring soon (0 unless the certificate
    # phase ran and carried a parseable not_after).
    cert_expiry, cert_detail, cert_expired = _cert_expiry(report)

    # Explainable risk model: the raw score is the sum of named, weighted signal
    # contributions (leaked secrets / source-maps weigh heaviest after a takeover —
    # the single worst hop). Numbers are unchanged from the old flat formula.
    risk_factors = _risk_factors(vuln_score, high, medium, secrets, takeovers,
                                 source_map_leaks, weak_cookies,
                                 graphql_introspection, infra_concentration,
                                 infra_detail, sla_breaches, sla_detail,
                                 cert_expiry, cert_detail)
    score = sum(f['points'] for f in risk_factors)
    level = _risk_level(score, high, secrets, takeovers, graphql_introspection)
    # Bounded 0–100 headline (the platform's single risk number).
    risk_100 = min(_SCORE_100_CEILING, score * _SCORE_TO_100)

    metrics = {
        'high': high, 'medium': medium, 'info': info,
        'secrets': secrets, 'weak_cookies': weak_cookies,
        'source_map_leaks': source_map_leaks, 'takeovers': takeovers,
        'graphql': graphql, 'graphql_introspection': graphql_introspection,
        'infra_concentration': infra_concentration,
        'sla_breaches': sla_breaches,
        'cert_expiry': cert_expiry, 'cert_expired': int(cert_expired),
        'non_ok_pages': non_ok, 'pages': pages,
        'cms': recon.get('cms') or [],
        'risk_100': risk_100,
        'attack_surface_score': surface_pts,
        'attack_surface_band': score_band(surface_pts),
    }

    key_findings: List[str] = []
    if secrets:
        key_findings.append(f'Утечки секретов/ключей: {secrets}')
    if takeovers:
        key_findings.append(f'Кандидаты на subdomain takeover: {takeovers}')
    if source_map_leaks:
        key_findings.append(f'Source maps с исходным кодом: {source_map_leaks}')
    if high:
        key_findings.append(f'Высокосерьёзных уязвимостей: {high}')
    if medium:
        key_findings.append(f'Средних замечаний: {medium}')
    if weak_cookies:
        key_findings.append(f'Слабых cookie: {weak_cookies}')
    if non_ok:
        key_findings.append(f'Страниц с не-2xx статусом: {non_ok}')

    # The most severe finding titles, in severity order, for quick context.
    top_findings = [
        f.get('title', '') for sev in ('High', 'Medium')
        for f in findings if f.get('severity') == sev
    ][:5]

    recommendations: List[str] = []
    if secrets:
        recommendations.append(
            f'Отозвать и заменить {secrets} утёкших ключ(а/ей); '
            f'убрать секреты из клиентского кода.')
    if takeovers:
        recommendations.append(
            f'Срочно проверить {takeovers} субдомен(а/ов) на takeover: '
            f'удалить висячие DNS-записи или вернуть контроль над ресурсом.')
    if source_map_leaks:
        recommendations.append(
            f'Убрать {source_map_leaks} публичных source map с исходниками '
            f'(или ограничить доступ) — они раскрывают оригинальный код.')
    if high:
        recommendations.append(
            f'Устранить {high} высокосерьёзных замечани(я/й) '
            f'(см. раздел Vulnerabilities).')
    if weak_cookies:
        recommendations.append(
            f'Усилить {weak_cookies} cookie: выставить Secure, HttpOnly, SameSite.')
    if non_ok:
        recommendations.append(
            f'Проверить {non_ok} страниц(ы) с не-2xx статусом (см. Site Map).')
    if medium and not high:
        recommendations.append(
            f'Рассмотреть {medium} средни(х) замечани(й).')
    if not recommendations:
        recommendations.append(
            'Существенных рисков не выявлено; повторить скан после изменений.')

    return {
        'risk_level': level,
        'risk_score': score,        # raw weighted score (weighting / sorting)
        'risk_100': risk_100,       # bounded 0–100 headline
        'metrics': metrics,
        'risk_factors': risk_factors,   # explainable score breakdown (F-R)
        'key_findings': key_findings,
        'top_findings': top_findings,
        'recommendations': recommendations,
    }


def load_latest_summary(search_dirs: List) -> Optional[Dict]:
    """Find the newest ``report.json`` under ``search_dirs`` and return its
    executive summary (building one on the fly for older reports that predate
    the field). Read-only; returns ``None`` if nothing usable is found.

    Lets the Dashboard reuse the last Full Collection verdict without re-running
    any scan — a pure aggregation over data already on disk.
    """
    candidates: List[Path] = []
    for d in search_dirs:
        if not d:
            continue
        base = Path(d).expanduser()
        if not base.is_dir():
            continue
        # Collection reports live at <base>/<domain>_<ts>/report.json (one level
        # deep). Bounded patterns avoid an unbounded '**' walk of a large
        # output tree (a Dashboard refresh must stay cheap).
        for pattern in ('report.json', '*/report.json'):
            candidates.extend(base.glob(pattern))
    if not candidates:
        return None
    for path in sorted(candidates, key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            report = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        summary = report.get('executive_summary') or build_summary(report)
        summary['_source'] = str(path)
        return summary
    return None


def display_cards(sec: Optional[Dict]) -> Dict:
    """Flatten a summary into display-ready strings for the Dashboard cards.

    ``None`` → an empty-state payload. Keeps formatting/routing in core so the
    GUI method stays a thin setter (architectural invariant I4) and the logic
    is testable without Qt.
    """
    if not sec:
        return {'available': False, 'risk_level': '—', 'risk_color': '#888',
                'risk_score': '0', 'risk_100': '0', 'secrets': '0',
                'high': '0', 'medium': '0', 'attack_surface': '0',
                'attack_surface_band': '—', 'source': ''}
    metrics = sec.get('metrics', {})
    level = sec.get('risk_level', '—')
    risk_100 = sec.get('risk_100', metrics.get('risk_100', 0))
    return {
        'available': True,
        'risk_level': level,
        'risk_color': RISK_COLORS.get(level, '#888'),
        'risk_score': str(sec.get('risk_score', 0)),
        'risk_100': str(risk_100),
        'secrets': str(metrics.get('secrets', 0)),
        'high': str(metrics.get('high', 0)),
        'medium': str(metrics.get('medium', 0)),
        'attack_surface': str(metrics.get('attack_surface_score', 0)),
        'attack_surface_band': str(metrics.get('attack_surface_band', '—')),
        'source': sec.get('_source', ''),
    }


def render_html(summary: Dict) -> str:
    """Render the executive summary as a self-contained inline-CSS fragment."""
    e = html.escape
    level = summary.get('risk_level', 'Clean')
    color = RISK_COLORS.get(level, '#555')
    score = summary.get('risk_score', 0)
    risk_100 = summary.get('risk_100',
                           summary.get('metrics', {}).get('risk_100', 0))

    banner = (
        f'<div style="background:{color};color:#fff;border-radius:6px;'
        f'padding:12px 16px;margin:8px 0;">'
        f'<span style="font-size:13px;opacity:.85;">Общий риск</span><br>'
        f'<span style="font-size:22px;font-weight:bold;">{e(level)}</span>'
        f'<span style="font-size:16px;opacity:.95;"> · {e(str(risk_100))}/100</span>'
        f'<span style="font-size:13px;opacity:.8;"> (raw {e(str(score))})</span>'
        f'</div>'
    )

    # "10-second" headline chip strip — the most important signals, compact and
    # prioritized (Cortex-Xpanse-style). Rendered above the banner; empty → a
    # single clean chip so the report still reads at a glance.
    hl = headline(summary)
    if hl['chips']:
        chip_html = ''.join(
            f'<span style="display:inline-block;background:'
            f'{HEADLINE_COLORS.get(c["severity"], "#666")};color:#fff;'
            f'border-radius:12px;padding:3px 10px;margin:2px 6px 2px 0;'
            f'font-size:12px;font-weight:bold;">{e(str(c["label"]))}</span>'
            for c in hl['chips'])
    else:
        chip_html = (
            f'<span style="display:inline-block;background:'
            f'{HEADLINE_COLORS["clean"]};color:#fff;border-radius:12px;'
            f'padding:3px 10px;font-size:12px;font-weight:bold;">'
            f'Критичной экспозиции не выявлено</span>')
    strip = (f'<div style="margin:8px 0 0;">'
             f'<span style="font-size:12px;color:#888;margin-right:8px;">'
             f'Главное:</span>{chip_html}</div>')
    banner = strip + banner

    def bullets(items, empty_note=''):
        if not items:
            return (f'<p style="font-size:13px;color:#2e7d32;">{e(empty_note)}</p>'
                    if empty_note else '')
        lis = ''.join(f'<li style="margin:3px 0;">{e(str(i))}</li>' for i in items)
        return f'<ul style="font-size:13px;margin:6px 0;padding-left:20px;">{lis}</ul>'

    # F-R3: explainable score breakdown — "why is the risk N" as a factor table.
    factors = summary.get('risk_factors', [])
    if factors:
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">{e(str(f.get("factor", "")))}'
            f'</td><td style="text-align:right;color:#c62828;font-weight:bold;">'
            f'+{e(str(f.get("points", 0)))}</td>'
            f'<td style="color:#888;padding-left:10px;">'
            f'{e(str(f.get("detail", "")))}</td></tr>'
            for f in factors)
        factors_html = (
            f'<h3 style="font-size:14px;margin:10px 0 2px;">Из чего риск</h3>'
            f'<table style="font-size:12px;border-collapse:collapse;">{rows}</table>')
    else:
        factors_html = ''

    findings = bullets(summary.get('key_findings', []),
                       'Значимых находок не зафиксировано.')
    recs = bullets(summary.get('recommendations', []))

    top = summary.get('top_findings', [])
    top_html = (
        f'<p style="font-size:12px;color:#666;margin:6px 0 0;">Ключевые: '
        f'{e("; ".join(t for t in top if t))}</p>' if any(top) else ''
    )

    # Optional LLM narrative (local Ollama) — supplementary prose UNDER the
    # authoritative deterministic verdict above. Rendered only when present, so
    # a report generated without Ollama is unchanged.
    narrative = summary.get('narrative')
    narrative_html = ''
    if narrative:
        model = summary.get('narrative_model', '')
        tag = f' · {e(str(model))}' if model else ''
        narrative_html = (
            f'<h3 style="font-size:14px;margin:12px 0 2px;">'
            f'AI-резюме <span style="font-weight:normal;color:#888;font-size:12px;">'
            f'(локальный Ollama{tag}; вердикт выше — детерминированный)</span></h3>'
            f'<p style="font-size:13px;margin:4px 0;white-space:pre-wrap;'
            f'background:#f5f5f5;border-radius:4px;padding:8px 12px;">'
            f'{e(str(narrative))}</p>'
        )

    return (
        f'{banner}'
        f'{factors_html}'
        f'<h3 style="font-size:14px;margin:10px 0 2px;">Находки</h3>{findings}{top_html}'
        f'<h3 style="font-size:14px;margin:12px 0 2px;">Рекомендации</h3>{recs}'
        f'{narrative_html}'
    )
