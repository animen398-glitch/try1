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


def _risk_level(score: int, high: int, secrets_critical: int, takeovers: int = 0,
                graphql_introspection: int = 0) -> str:
    """Map weighted signals to a verdict. Thresholds are intentionally simple
    and fixed so the verdict is reproducible and easy to reason about. A leaked
    *high-value* credential (cloud/payment/VCS key) and a subdomain takeover are
    both clear-cut Critical signals; an open GraphQL schema (introspection) is a
    clear-cut High signal. A leaked generic/opaque key needs no gate here — it is
    a High vuln finding, so it already lands at High via the ``high`` count."""
    if secrets_critical > 0 or takeovers > 0 or high >= 3 or score >= 20:
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
# here — and neither do leaking source maps, open GraphQL, weak cookies, nor
# subdomain takeovers: those are all first-class vuln findings (source maps +
# GraphQL + takeovers folded into the vuln phase; weak cookies emitted by
# VulnScanner._check_cookies), counted once via their severity, not a second time
# as a dedicated factor — and neither do leaked secrets: they are first-class
# vuln findings too (folded into the vuln phase by CollectionRunner._secret_findings),
# counted once via their High severity. A high-value secret / takeover still forces
# a Critical verdict via _risk_level (a clear-cut level gate, not a score addend).
RISK_WEIGHTS = {
    'infra_concentration': 2,     # shared-infra choke point / blast radius (F-R4)
    'sla_breach': 1,              # remediation past its deadline — overdue surcharge (F-R5)
    'cert_expiry': 2,            # served TLS cert expired / expiring soon (F-R6)
    'regression': 2,             # a fixed finding came back this scan (F-R7)
}

# Secret types treated as generic / opaque / not-high-value (everything else —
# AWS / Google / Stripe-secret / GitHub / Slack / Twilio / … — is high-value, so a
# new exact-format provider rule defaults to high-value, not silently demoted).
# This split no longer weights the score (every plausible secret is one High vuln
# finding); it decides the *verdict gate* only — a high-value key forces Critical
# via _risk_level, a generic-only set lands at High via the finding's severity.
# ``Stripe Publishable`` (pk_live) is designed to be public; ``JWT`` / ``Bearer``
# are opaque tokens often not secret; the two ``Generic`` rules are low-confidence.
_GENERIC_SECRET_TYPES = frozenset({
    'Generic API Key', 'Generic Secret', 'Bearer Token', 'JWT',
    'Stripe Publishable',
})


def is_high_value_secret(secret_type: str) -> bool:
    """Whether a secret *type* is a high-value credential (vs generic/opaque).

    The single source of truth for secret severity tiering (``_GENERIC_SECRET_TYPES``),
    shared by the risk gate (_secret_signal) and the Scan-Diff secret events so the
    two never diverge into separate scoring systems. Unknown types default to
    high-value (a new exact-format provider rule is not silently demoted)."""
    return str(secret_type).strip() not in _GENERIC_SECRET_TYPES


_SECRET_TITLE_PREFIX = 'Leaked secret:'


def _is_high_value_secret_finding(finding: Dict) -> bool:
    """Whether a secret-category finding is a high-value credential.

    The tier is not stored on the finding (all secret findings are High severity),
    so recover the vendor type from the producer's stable title
    ``'Leaked secret: {type}'`` and reuse the ``is_high_value_secret`` SSOT. An
    unrecognisable title degrades to high-value (the conservative default)."""
    title = str(finding.get('title', ''))
    stype = (title.split(_SECRET_TITLE_PREFIX, 1)[1].strip()
             if _SECRET_TITLE_PREFIX in title else '')
    return is_high_value_secret(stype)

# How close to expiry (days) a still-valid leaf cert is flagged as a risk signal.
CERT_EXPIRY_WARN_DAYS = 14


def _risk_factors(vuln_score: int, high: int, medium: int,
                  infra_concentration: int = 0,
                  infra_detail: str = '', sla_breaches: int = 0,
                  sla_detail: str = '', cert_expiry: int = 0,
                  cert_detail: str = '', regressions: int = 0) -> List[Dict]:
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

    add('Концентрация на инфраструктуре', infra_concentration,
        'infra_concentration', infra_detail)
    add('Просроченная ремедиация (SLA)', sla_breaches, 'sla_breach', sla_detail)
    add('TLS-сертификат истёк/истекает', cert_expiry, 'cert_expiry', cert_detail)
    add('Регрессия (переоткрытые находки)', regressions, 'regression',
        'фикс не удержался')
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


def _reopened_regressions(report: Dict) -> int:
    """Findings that were fixed and came back *this scan* — regressions (F-R7).

    Reads the per-scan ``reopened`` count the findings sync already stamped onto
    ``report['findings']`` (a finding auto-FIXED in an earlier scan that
    reappeared → REOPENED). A regression means a previous fix did not hold — a
    worse posture than a fresh finding of the same severity, so it adds a light
    surcharge on top of the severity weight already counted (the reopened finding
    is OPEN again, so it is already in the vuln score). ``0`` for reports without
    a synced findings block (older reports / tests)."""
    return _int((report.get('findings') or {}).get('reopened'))


def _cve_summary(report: Dict) -> Dict:
    """CVE Intelligence rollup for the display **metric** (EPIC 3).

    Reads the count-by-severity the CVE phase (``phases.osv``) already stamped on
    the report. Deliberately NOT a risk-score addend: each correlated CVE is folded
    into the vuln phase as a finding and counted once via its severity (the score
    invariant, §12) — this is the explainable "CVE Risk Score" *view* (how many
    known CVEs, how severe), not a second contribution. Zero when the opt-in CVE
    phase didn't run (older reports / default pipeline)."""
    data = (report.get('phases', {}).get('osv') or {}).get('data') or {}
    s = data.get('cve_summary')
    if not isinstance(s, dict):
        return {'total': 0, 'high': 0, 'medium': 0, 'info': 0}
    return {'total': _int(s.get('total')), 'high': _int(s.get('high')),
            'medium': _int(s.get('medium')), 'info': _int(s.get('info'))}


def _exposure_clusters(report: Dict) -> Dict:
    """Asset-level shared-infrastructure exposure for the display **metric** (EPIC 5).

    Reads the asset-graph rollup (``report['asset_graph']``) the Asset Correlation
    Engine already stamped: how many infrastructure nodes concentrate ≥2 assets
    (single points of exposure) and the largest such cluster. Deliberately NOT a
    score addend — finding-level infra concentration is already counted by
    ``_infra_concentration`` (F-R4); this is the asset-topology view, a metric/chip
    only. Zero when the asset graph didn't run (older reports)."""
    s = (report.get('asset_graph') or {}).get('summary') or {}
    return {'clusters': _int(s.get('clusters')),
            'largest': _int(s.get('largest_cluster'))}


def _asset_criticality(report: Dict) -> Dict:
    """Asset Criticality rollup for the display **metric** (EPIC 9).

    Reads the ranking the Asset Criticality engine already stamped
    (``report['asset_criticality']``): how many assets are high-criticality and the
    top score. Deliberately NOT a score addend — criticality is itself derived from
    blast radius + attached findings (already in the verdict via those findings);
    this is the "which asset matters most" view, a metric/chip only. Zero when the
    engine didn't run (older reports)."""
    s = (report.get('asset_criticality') or {}).get('summary') or {}
    return {'critical_assets': _int(s.get('high_criticality')),
            'top_asset_criticality': _int(s.get('top_criticality'))}


def _intelligence(report: Dict) -> Dict:
    """Core Intelligence rollup for the display **metric** (EPIC 7).

    Reads the priority/confidence summary the intelligence layer already stamped
    (``report['intelligence']``). Not a score addend — priority is itself derived
    from severity (already in the score) amplified by exposure/SLA; this surfaces
    the top priority and how many findings are high-confidence. Zero when the
    intelligence layer didn't run (older reports)."""
    s = (report.get('intelligence') or {}).get('summary') or {}
    return {'top_priority': _int(s.get('top_priority')),
            'high_confidence': _int(s.get('high_confidence'))}


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


def _secret_signal(api: Dict) -> Dict:
    """Risk-bearing secret signal for the metrics + the verdict gate.

    Secrets are scored via the High vuln findings ``CollectionRunner._secret_findings``
    folds into the vuln phase (so they are NOT a dedicated score factor); this
    helper only supplies the display metrics (``secrets`` / ``secrets_high_value``
    / ``secrets_detected``) and the ``_risk_level`` Critical gate. Two filters over
    what the always-on ``api`` phase detected:
      * *plausibility* — a key whose structure is a clear placeholder / false
        positive (``secret_validator`` → ``invalid_format`` — e.g.
        ``your_api_key_here``) is dropped (``valid_format`` / ``unverifiable`` count);
      * *severity tier* — a high-value credential (cloud/payment/VCS/messaging key)
        vs a generic/opaque match (see ``_GENERIC_SECRET_TYPES``); only the count of
        high-value keys forces a Critical verdict.

    Derive-on-read over ``api['details']`` — the matched values are already there,
    so this is offline and re-fetch-free (invariant I3) and reuses the single
    validation source of truth (``core.secret_validator``). Falls back to a flat
    ``keys_found`` (treated as high-value) when no per-key details exist (legacy
    reports / tests). Returns ``{plausible, detected, critical, generic}``."""
    detected = _int(api.get('keys_found'))
    details = api.get('details')
    if not isinstance(details, dict) or not details:
        return {'plausible': detected, 'detected': detected,
                'critical': detected, 'generic': 0}
    from core.secret_validator import INVALID, validate
    critical = generic = 0
    for key_type, values in details.items():
        for v in (values if isinstance(values, list) else [values]):
            if validate(str(key_type), str(v)).get('status') == INVALID:
                continue
            if is_high_value_secret(key_type):
                critical += 1
            else:
                generic += 1
    return {'plausible': critical + generic, 'detected': detected,
            'critical': critical, 'generic': generic}


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
        # Critical chip only when a high-value credential is among them; a
        # generic-only set is a High signal (mirrors the verdict gate).
        add(_plural(secrets, 'Secret'),
            'critical' if _int(m.get('secrets_high_value')) else 'high')
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
    cve_total = _int(m.get('cve_total'))
    if cve_total:
        # Known CVEs in detected components (severity by the worst tier present).
        add(f'{cve_total} CVE', 'high' if _int(m.get('cve_high')) else 'medium')
    exposure_clusters = _int(m.get('exposure_clusters'))
    if exposure_clusters:
        # Asset-level shared-infra single points of exposure (blast radius, EPIC 5);
        # labelled "co-hosted" to distinguish from F-R4's finding-concentration chip.
        add(f'{exposure_clusters}× co-hosted', 'medium')
    critical_assets = _int(m.get('critical_assets'))
    if critical_assets:
        # High-criticality assets (EPIC 9) — which assets matter most (display).
        add(_plural(critical_assets, 'critical asset'), 'medium')
    regressions = _int(m.get('regressions'))
    if regressions:
        add(f'{regressions}× regression', 'high')
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
    all_findings = findings   # full list (pre active-filter) — for secret detection

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
    # Secrets: now first-class High vuln findings (folded by
    # CollectionRunner._secret_findings) → already in vuln_score / the high count
    # above, NOT a dedicated factor. This signal only drives the display metrics
    # (``secrets`` / ``secrets_high_value``) and the Critical verdict gate.
    # Status-aware: when secrets are findings, derive the counts from the *active*
    # (triage-filtered) secret findings, so marking a secret FALSE_POSITIVE /
    # IGNORED / FIXED relaxes the verdict gate too — not just the score. Fall back
    # to the api signal for legacy reports that have no secret findings.
    # ``secrets_detected`` keeps the raw api match count for transparency.
    secrets_detected = _int(api.get('keys_found'))
    if any(isinstance(f, dict) and f.get('category') == 'secret'
           for f in all_findings):
        active_secrets = [f for f in findings if isinstance(f, dict)
                          and f.get('category') == 'secret']
        secrets = len(active_secrets)
        secrets_high_value = sum(1 for f in active_secrets
                                 if _is_high_value_secret_finding(f))
    else:
        sig = _secret_signal(api)
        secrets = sig['plausible']
        secrets_high_value = sig['critical']
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
    # F-R7: regressions — findings that were fixed and reappeared this scan
    # (0 unless the findings sync stamped a reopened count onto the report).
    regressions = _reopened_regressions(report)
    # CVE Intelligence rollup — a display metric only (CVEs already count once via
    # their finding severity in the vuln score; this is not a second score addend).
    cve = _cve_summary(report)
    # Asset-level shared-infra exposure (EPIC 5) — display metric only (finding-level
    # infra concentration is already scored by F-R4; this is the asset-topology view).
    exposure = _exposure_clusters(report)
    # Core Intelligence (EPIC 7) — top priority + high-confidence count (display).
    intel = _intelligence(report)
    # Asset Criticality (EPIC 9) — how many assets are high-criticality + top score
    # (display metric only; criticality is not a risk-score addend).
    asset_crit = _asset_criticality(report)

    # Explainable risk model: the raw score is the sum of named, weighted signal
    # contributions. Leaked secrets / leaking source maps / open GraphQL / weak
    # cookies / subdomain takeovers are all counted via the vuln findings they
    # produce, not a dedicated factor (no double count); a high-value secret or a
    # takeover still forces a Critical verdict below via _risk_level.
    risk_factors = _risk_factors(vuln_score, high, medium,
                                 infra_concentration,
                                 infra_detail, sla_breaches, sla_detail,
                                 cert_expiry, cert_detail, regressions)
    score = sum(f['points'] for f in risk_factors)
    level = _risk_level(score, high, secrets_high_value, takeovers,
                        graphql_introspection)
    # Bounded 0–100 headline (the platform's single risk number).
    risk_100 = min(_SCORE_100_CEILING, score * _SCORE_TO_100)

    metrics = {
        'high': high, 'medium': medium, 'info': info,
        'secrets': secrets, 'secrets_detected': secrets_detected,
        'secrets_high_value': secrets_high_value,
        'weak_cookies': weak_cookies,
        'source_map_leaks': source_map_leaks, 'takeovers': takeovers,
        'graphql': graphql, 'graphql_introspection': graphql_introspection,
        'infra_concentration': infra_concentration,
        'sla_breaches': sla_breaches,
        'cert_expiry': cert_expiry, 'cert_expired': int(cert_expired),
        'regressions': regressions,
        'cve_total': cve['total'], 'cve_high': cve['high'],
        'cve_medium': cve['medium'],
        'exposure_clusters': exposure['clusters'],
        'exposure_largest': exposure['largest'],
        'top_priority': intel['top_priority'],
        'high_confidence_findings': intel['high_confidence'],
        'critical_assets': asset_crit['critical_assets'],
        'top_asset_criticality': asset_crit['top_asset_criticality'],
        'non_ok_pages': non_ok, 'pages': pages,
        'cms': recon.get('cms') or [],
        'risk_100': risk_100,
        'attack_surface_score': surface_pts,
        'attack_surface_band': score_band(surface_pts),
    }

    key_findings: List[str] = []
    if secrets:
        suppressed = (f' (из {secrets_detected} обнаруженных; '
                      f'остальные — плейсхолдеры)'
                      if secrets_detected > secrets else '')
        key_findings.append(f'Утечки секретов/ключей: {secrets}{suppressed}')
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
