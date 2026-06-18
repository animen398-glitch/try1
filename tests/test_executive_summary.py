"""Deterministic executive summary — risk verdict, findings, recommendations.

All offline and model-free: pure functions over a collection ``report`` dict.
"""

from datetime import datetime, timedelta

from core import executive_summary as es


def _report(*, high=0, medium=0, info=0, risk_score=0, secrets=0,
            weak_cookies=0, status_summary=None, findings=None, cms=None,
            secret_details=None):
    # A weak cookie is a first-class Medium vuln finding (VulnScanner._check_cookies),
    # so model it as such: it counts once, via the vuln phase's severity, not via a
    # dedicated risk factor. Bump the medium count / risk_score the way the real
    # pipeline does (Medium weighs 2) so the score math matches production.
    findings = list(findings or [])
    medium += weak_cookies
    risk_score += weak_cookies * 2
    for i in range(weak_cookies):
        findings.append({'severity': 'Medium', 'category': 'cookie',
                         'location': f'cookie:c{i}',
                         'title': f'Weakly protected cookie c{i}'})
    # Secrets are first-class High vuln findings (CollectionRunner._secret_findings):
    # each plausible key (placeholders dropped by the structural validator) folds in
    # as High (weight 5), counted once via severity — not a dedicated factor. Model
    # that here. secret_details ({type: [values]}) exercises the validator path;
    # without it the legacy flat keys_found is treated as N plausible high-value keys.
    from core.secret_validator import INVALID as _SV_INVALID
    from core.secret_validator import validate as _sv_validate
    api_data = {'keys_found': secrets}
    if secret_details is not None:
        api_data = {'keys_found': sum(len(v) for v in secret_details.values()),
                    'details': secret_details}
        plausible = [(t, v) for t, vals in secret_details.items() for v in vals
                     if _sv_validate(str(t), str(v)).get('status') != _SV_INVALID]
    else:
        plausible = [('secret', f'k{i}') for i in range(secrets)]
    high += len(plausible)
    risk_score += len(plausible) * 5
    for j, (ktype, _v) in enumerate(plausible):
        findings.append({'severity': 'High', 'category': 'secret',
                         'location': 'secret', 'discriminator': f'{ktype}:{j}',
                         'title': f'Leaked secret: {ktype}'})
    return {
        'phases': {
            'recon': {'data': {'cms': cms or []}},
            'api': {'data': api_data},
            'capture': {'data': {'pages_captured': 3,
                                 'status_summary': status_summary or {}}},
            'cookies': {'data': {'weak': weak_cookies}},
            'vulns': {
                'summary': {'high': high, 'medium': medium, 'info': info,
                            'risk_score': risk_score},
                'findings': findings,
            },
        },
    }


# ── risk level thresholds ───────────────────────────────────────────────────

def test_clean_when_no_signal():
    s = es.build_summary(_report())
    assert s['risk_level'] == 'Clean'
    assert s['risk_score'] == 0
    # A clean report still yields a (reassuring) recommendation.
    assert s['recommendations']


def test_secrets_force_critical():
    s = es.build_summary(_report(secrets=1))
    assert s['risk_level'] == 'Critical'
    # secret weighs 5 into the score.
    assert s['risk_score'] == 5


def test_placeholder_secret_does_not_force_critical():
    # A lone placeholder ("your_api_key_here") is a false positive: it must not
    # count as a risk-bearing secret nor force a Critical verdict.
    s = es.build_summary(_report(
        secret_details={'Generic API Key': ['your_api_key_here']}))
    assert s['metrics']['secrets'] == 0
    assert s['metrics']['secrets_detected'] == 1
    assert s['risk_level'] == 'Clean'
    assert s['risk_score'] == 0


def test_plausible_secret_still_forces_critical():
    # A structurally valid key (or an unverifiable-but-plausible one) still counts.
    s = es.build_summary(_report(
        secret_details={'AWS Access Key': ['AKIAIOSFODNN7EXAMPLE']}))
    assert s['metrics']['secrets'] == 1
    assert s['risk_level'] == 'Critical'
    assert s['risk_score'] == 5


def test_mixed_secrets_count_only_plausible():
    s = es.build_summary(_report(secret_details={
        'AWS Access Key': ['AKIAIOSFODNN7EXAMPLE'],     # plausible (unverifiable type below is exact)
        'Generic API Key': ['your_api_key_here', 'changeme']}))  # 2 placeholders
    assert s['metrics']['secrets'] == 1            # only the AWS key counts
    assert s['metrics']['secrets_detected'] == 3
    assert s['risk_score'] == 5
    # The key finding notes the suppressed placeholders for transparency.
    assert any('из 3 обнаруженных' in k for k in s['key_findings'])


def test_legacy_keys_found_unchanged_without_details():
    # No per-key details (older report) → flat keys_found, behaviour byte-for-byte.
    s = es.build_summary(_report(secrets=2))
    assert s['metrics']['secrets'] == 2
    assert s['metrics']['secrets_detected'] == 2
    assert s['risk_level'] == 'Critical'


def test_generic_secret_is_high_not_critical():
    # A plausible but generic/opaque key (not a high-value credential) is a High
    # vuln finding → High verdict, not Critical (no high-value gate).
    s = es.build_summary(_report(
        secret_details={'Generic API Key': ['aB3cD4eF5gH6iJ7k']}))
    assert s['metrics']['secrets'] == 1
    assert s['metrics']['secrets_high_value'] == 0
    assert s['risk_score'] == 5                       # one High finding
    assert s['risk_level'] == 'High'
    # Secrets are no longer a dedicated factor — they ride the vuln factor.
    assert 'Утёкшие секреты' not in {f['factor'] for f in s['risk_factors']}
    # Headline chip downgrades to High too (mirrors the verdict).
    assert es.headline(s)['chips'][0]['severity'] == 'high'


def test_high_value_secret_forces_critical_via_gate():
    # A high-value credential (AWS) + a generic key: both are High findings (5
    # each), and the high-value key forces Critical via the verdict gate.
    s = es.build_summary(_report(secret_details={
        'AWS Access Key': ['AKIAIOSFODNN7EXAMPLE'],
        'Generic API Key': ['aB3cD4eF5gH6iJ7k']}))
    assert s['metrics']['secrets'] == 2
    assert s['metrics']['secrets_high_value'] == 1
    assert s['risk_score'] == 5 + 5                   # two High findings
    assert s['risk_level'] == 'Critical'


def test_triaged_secret_relaxes_critical_gate():
    # A high-value secret finding forces Critical; triaging it away (FALSE_POSITIVE)
    # drops it from the count AND the verdict gate, not just the score.
    secret = {'severity': 'High', 'category': 'secret', 'location': 'https://x',
              'title': 'Leaked secret: AWS Access Key', 'status': 'OPEN'}
    s = es.build_summary(_report(findings=[secret]))
    assert s['metrics']['secrets'] == 1
    assert s['metrics']['secrets_high_value'] == 1
    assert s['risk_level'] == 'Critical'

    fp = dict(secret, status='FALSE_POSITIVE')
    s2 = es.build_summary(_report(findings=[fp]))
    assert s2['metrics']['secrets'] == 0
    assert s2['metrics']['secrets_high_value'] == 0
    assert s2['risk_level'] != 'Critical'


def test_secrets_are_not_a_dedicated_factor():
    # Convergence: secrets count once via their High finding severity, so there is
    # no separate secret weight any more.
    assert 'secrets' not in es.RISK_WEIGHTS
    assert not hasattr(es, 'SECRET_WEIGHTS')


def test_three_high_is_critical():
    s = es.build_summary(_report(high=3, risk_score=15))
    assert s['risk_level'] == 'Critical'


def test_single_high_is_high():
    s = es.build_summary(_report(high=1, risk_score=5))
    assert s['risk_level'] == 'High'


def test_medium_band():
    # weak cookies (Medium findings, 2 each) push score into the Medium band
    # without any high.
    s = es.build_summary(_report(weak_cookies=2))
    assert s['risk_score'] == 4
    assert s['risk_level'] == 'Medium'


def test_low_band():
    s = es.build_summary(_report(info=2, risk_score=2))
    assert s['risk_level'] == 'Low'


# ── unified 0–100 score + new signals (P3) ──────────────────────────────────

def test_risk_100_is_bounded_and_scaled():
    # raw 5 (one secret) → 20/100; clean → 0/100.
    assert es.build_summary(_report(secrets=1))['risk_100'] == 20
    assert es.build_summary(_report())['risk_100'] == 0
    # Saturates at 100 for a very high raw score.
    big = es.build_summary(_report(high=5, risk_score=40, secrets=3))
    assert big['risk_100'] == 100


def test_risk_100_in_metrics_and_cards():
    s = es.build_summary(_report(weak_cookies=2))     # raw 4 → 16/100
    assert s['metrics']['risk_100'] == 16
    c = es.display_cards(s)
    assert c['risk_100'] == '16'


def test_takeover_signal_forces_critical_and_weights():
    # Collection folds each takeover candidate into the vuln phase as a High
    # finding (here: 2 High → vuln_score 10); the subdomains metric still drives
    # the Critical verdict. Counted once via the finding, not a dedicated factor.
    report = _report(high=2, risk_score=10)
    report['phases']['subdomains'] = {
        'data': {'summary': {'takeover_candidates': ['x.ex.com', 'y.ex.com']}}}
    s = es.build_summary(report)
    assert s['risk_level'] == 'Critical'              # takeover → Critical
    assert s['metrics']['takeovers'] == 2
    assert s['risk_score'] == 10                       # 2 × High(5), via findings
    assert any('takeover' in r.lower() for r in s['recommendations'])
    # no dedicated takeover factor any more (counted via the High findings)
    assert 'takeovers' not in es.RISK_WEIGHTS
    assert all(f['factor'] != 'Subdomain takeover' for f in s['risk_factors'])


def test_source_map_leak_surfaced_but_scored_via_findings():
    # Source-map leaks are surfaced as a metric (for the heatmap/headline) and a
    # recommendation, but they no longer add a *dedicated* risk factor — the
    # signal is scored once via the High finding the security phase folds in
    # (here only the summary is present, so the dedicated path contributes 0).
    report = _report()
    report['phases']['security'] = {
        'data': {'summary': {'maps_with_content': 2}}}
    s = es.build_summary(report)
    assert s['metrics']['source_map_leaks'] == 2
    assert s['risk_score'] == 0                         # no dedicated factor
    assert 'Source map с исходниками' not in {
        f['factor'] for f in s['risk_factors']}
    assert any('source map' in r.lower() for r in s['recommendations'])


def test_new_signals_absent_by_default():
    s = es.build_summary(_report(secrets=1))
    assert s['metrics']['takeovers'] == 0
    assert s['metrics']['source_map_leaks'] == 0
    assert s['metrics']['graphql'] == 0
    assert s['metrics']['graphql_introspection'] == 0
    assert s['risk_score'] == 5                         # unchanged formula


def test_graphql_exposure_surfaced_in_metrics():
    report = _report()
    report['phases']['security'] = {
        'data': {'summary': {'graphql': 2, 'graphql_introspection': 1}}}
    s = es.build_summary(report)
    assert s['metrics']['graphql'] == 2
    assert s['metrics']['graphql_introspection'] == 1
    # An open GraphQL schema is surfaced as a metric and stays a clear-cut High
    # signal (the level gate), but it is no longer a *dedicated* score factor —
    # it scores once via the High finding the security phase folds in (absent
    # here, only the summary is present, so the dedicated path contributes 0).
    assert s['risk_score'] == 0
    assert s['risk_level'] == 'High'
    assert 'GraphQL introspection' not in {f['factor'] for f in s['risk_factors']}


def test_reachable_graphql_without_introspection_scores_zero():
    # A merely reachable GraphQL API (no introspection) is not a risk signal here.
    report = _report()
    report['phases']['security'] = {
        'data': {'summary': {'graphql': 3, 'graphql_introspection': 0}}}
    s = es.build_summary(report)
    assert s['risk_score'] == 0 and s['risk_level'] == 'Clean'


def test_render_html_shows_0_100_headline():
    out = es.render_html(es.build_summary(_report(secrets=1, high=2, risk_score=10)))
    assert '/100' in out


# ── findings & recommendations ──────────────────────────────────────────────

def test_recommendations_track_signals():
    s = es.build_summary(_report(
        secrets=2, high=1, weak_cookies=3,
        status_summary={'4xx': 1, '5xx': 1, 'err': 1},
    ))
    text = ' '.join(s['recommendations'])
    assert 'ключ' in text                    # rotate secrets
    assert 'Vulnerabilities' in text         # remediate high
    assert 'SameSite' in text                # harden cookies
    assert 'Site Map' in text                # review non-2xx pages
    assert s['metrics']['non_ok_pages'] == 3


def test_top_findings_are_severity_ordered():
    s = es.build_summary(_report(
        high=1, medium=1, risk_score=7,
        findings=[
            {'severity': 'Medium', 'title': 'M1'},
            {'severity': 'High', 'title': 'H1'},
            {'severity': 'Info', 'title': 'I1'},
        ],
    ))
    # High titles come before Medium; Info excluded.
    assert s['top_findings'] == ['H1', 'M1']


def test_tolerates_missing_phases():
    # An almost-empty report must not raise.
    s = es.build_summary({'phases': {}})
    assert s['risk_level'] == 'Clean'
    assert s['metrics']['pages'] == 0


def test_tolerates_non_numeric_values():
    bad = {'phases': {'vulns': {'summary': {'high': None, 'risk_score': 'x'}},
                      'api': {'data': {'keys_found': None}}}}
    s = es.build_summary(bad)
    assert s['risk_score'] == 0


# ── render_html (offline fragment) ──────────────────────────────────────────

def test_render_html_is_offline_and_coloured():
    s = es.build_summary(_report(secrets=1, high=2, risk_score=10))
    out = es.render_html(s)
    assert 'http://' not in out and 'https://' not in out
    assert '<script' not in out.lower()
    assert 'Critical' in out
    assert es.RISK_COLORS['Critical'] in out
    assert 'Рекомендации' in out


def test_render_html_escapes_finding_text():
    s = es.build_summary(_report(
        high=1, risk_score=5,
        findings=[{'severity': 'High', 'title': '<img src=x>'}]))
    out = es.render_html(s)
    assert '<img src=x>' not in out
    assert '&lt;img' in out


# ── headline ("10-second" chip strip) ─────────────────────────────────────────

def test_headline_prioritizes_secrets_and_caps():
    s = es.build_summary(_report(secrets=2, high=4, weak_cookies=1, medium=3))
    hl = es.headline(s)
    assert hl['chips'][0] == {'label': '2 Secrets', 'severity': 'critical'}
    # severity priority: secrets(crit) before high before cookies/medium
    sevs = [c['severity'] for c in hl['chips']]
    assert sevs == sorted(sevs, key=lambda x: ('critical', 'high', 'medium',
                                               'low', 'info').index(x))
    assert len(hl['chips']) <= 6
    assert hl['risk_level'] == s['risk_level']


def test_headline_singular_plural():
    one = es.headline(es.build_summary(_report(secrets=1)))
    assert one['chips'][0]['label'] == '1 Secret'      # no trailing 's'


def test_headline_empty_when_clean():
    assert es.headline(es.build_summary(_report()))['chips'] == []


def test_render_html_includes_headline_strip():
    html = es.render_html(es.build_summary(_report(secrets=1)))
    assert 'Главное:' in html and '1 Secret' in html


def test_render_html_clean_chip_when_no_signal():
    html = es.render_html(es.build_summary(_report()))
    assert 'Критичной экспозиции не выявлено' in html


# ── F-R1: explainable risk score (equivalence + breakdown) ────────────────────

def test_risk_factors_sum_to_score():
    s = es.build_summary(_report(high=2, medium=1, risk_score=12, secrets=1,
                                 weak_cookies=2))
    assert sum(f['points'] for f in s['risk_factors']) == s['risk_score']


def test_risk_score_unchanged_by_refactor():
    # Score = vuln_score + secrets*5 (+others=0). Weak cookies fold into vuln_score
    # as Medium findings (2 each) rather than a dedicated factor — same total, 19.
    s = es.build_summary(_report(high=1, medium=0, risk_score=10, secrets=1,
                                 weak_cookies=2))
    assert s['risk_score'] == (10 + 2 * 2) + 1 * 5     # == 19, as before


def test_risk_factors_named_and_weighted():
    s = es.build_summary(_report(secrets=2, weak_cookies=1))
    by_name = {f['factor']: f for f in s['risk_factors']}
    # Secrets (2 × High = 10) and the weak cookie (1 × Medium = 2) are all counted
    # once via the vuln factor's severity — no dedicated 'Утёкшие секреты' /
    # 'Слабые cookie' factor (no double count).
    assert 'Утёкшие секреты' not in by_name
    assert 'Слабые cookie' not in by_name
    assert by_name['Уязвимости (vuln-скан)']['points'] == 2 * 5 + 1 * 2
    # Heaviest factor first.
    assert s['risk_factors'][0]['points'] >= s['risk_factors'][-1]['points']


def test_risk_factors_empty_when_clean():
    assert es.build_summary(_report())['risk_factors'] == []


def test_weak_cookie_counted_once_not_double():
    # A weak cookie surfaces both as a metric (cookies.data.weak) and as a Medium
    # vuln finding. It must score once (via the finding's severity, 2), not twice.
    s = es.build_summary(_report(weak_cookies=1))
    assert s['risk_score'] == 2                       # 1 × Medium(2), not 2+2
    assert s['metrics']['weak_cookies'] == 1          # display metric kept
    assert 'weak_cookies' not in es.RISK_WEIGHTS      # no dedicated factor


# ── F-R4: shared-infra concentration (blast radius) folds into the score ──────

def _infra_node(node='AS13335', type='asn', host_count=3, findings_count=5,
                worst='high'):
    return {'type': type, 'node': node, 'host_count': host_count,
            'findings_count': findings_count, 'worst': worst}


def test_infra_concentration_adds_weighted_factor():
    r = _report(weak_cookies=1)                       # base score 2
    r['correlation'] = {'infra_exposure': [
        _infra_node('AS13335', 'asn', host_count=3),
        _infra_node('1.2.3.0/24', 'netblock', host_count=3),
        _infra_node('1.2.3.4', 'ip', host_count=1),   # single host → not counted
    ]}
    s = es.build_summary(r)
    by_name = {f['factor']: f for f in s['risk_factors']}
    factor = by_name['Концентрация на инфраструктуре']
    assert factor['count'] == 2                        # asn + netblock (≥2 hosts)
    assert factor['weight'] == 2
    assert factor['points'] == 2 * 2
    assert 'AS13335' in factor['detail']               # worst-first node named
    assert s['risk_score'] == 2 + 2 * 2                # base + amplifier
    assert s['metrics']['infra_concentration'] == 2


def test_infra_concentration_absent_leaves_score_unchanged():
    # No correlation phase (the common case) → no new factor, score as before.
    base = es.build_summary(_report(weak_cookies=1))
    assert base['metrics']['infra_concentration'] == 0
    assert 'Концентрация на инфраструктуре' not in {
        f['factor'] for f in base['risk_factors']}
    # A correlation with only single-host nodes also adds nothing.
    r = _report(weak_cookies=1)
    r['correlation'] = {'infra_exposure': [_infra_node(host_count=1)]}
    assert es.build_summary(r)['risk_score'] == base['risk_score']


def test_infra_concentration_chip_in_headline():
    r = _report()
    r['correlation'] = {'infra_exposure': [_infra_node(host_count=4)]}
    hl = es.headline(es.build_summary(r))
    assert any('shared infra' in c['label'] for c in hl['chips'])


# ── F-R5: overdue-remediation (SLA breach) surcharge folds into the score ─────

def _with_sla(report, breached=0, by_severity=None):
    """Inject the F1 SLA block the findings sync stamps onto a real report."""
    report['findings'] = {'sla': {'breached': breached,
                                  'by_severity': by_severity or {}}}
    return report


def test_sla_breach_adds_weighted_surcharge():
    r = _with_sla(_report(weak_cookies=1), breached=3,        # base score 2
                  by_severity={'high': {'breached': 2}, 'low': {'breached': 1}})
    s = es.build_summary(r)
    by_name = {f['factor']: f for f in s['risk_factors']}
    factor = by_name['Просроченная ремедиация (SLA)']
    assert factor['count'] == 3
    assert factor['weight'] == 1
    assert factor['points'] == 3 * 1
    assert 'худшая — high' in factor['detail']              # worst overdue severity
    assert s['risk_score'] == 2 + 3 * 1                     # base + surcharge
    assert s['metrics']['sla_breaches'] == 3


def test_sla_breach_absent_leaves_score_unchanged():
    # No findings block (older reports / tests) → no new factor, score as before.
    base = es.build_summary(_report(weak_cookies=1))
    assert base['metrics']['sla_breaches'] == 0
    assert 'Просроченная ремедиация (SLA)' not in {
        f['factor'] for f in base['risk_factors']}
    # A synced findings block with zero breaches also adds nothing.
    r = _with_sla(_report(weak_cookies=1), breached=0)
    assert es.build_summary(r)['risk_score'] == base['risk_score']


def test_sla_breach_is_amplifier_not_clearcut():
    # An overdue backlog nudges the score but does not by itself force High/Critical
    # (mirrors infra_concentration — _risk_level is untouched).
    r = _with_sla(_report(), breached=2,
                  by_severity={'medium': {'breached': 2}})
    s = es.build_summary(r)
    assert s['risk_score'] == 2          # 2 breaches × weight 1
    assert s['risk_level'] == 'Low'      # score 2 → Low band, not escalated


def test_sla_breach_chip_in_headline():
    r = _with_sla(_report(), breached=4,
                  by_severity={'critical': {'breached': 4}})
    hl = es.headline(es.build_summary(r))
    assert any('SLA overdue' in c['label'] for c in hl['chips'])


# ── F-R6: served TLS cert expiry amplifier ────────────────────────────────────

def _with_cert(report, not_after):
    """Inject the (opt-in) certificate phase carrying a served-cert not_after."""
    report['phases']['certificate'] = {'data': {'not_after': not_after}}
    return report


def test_parse_cert_date_handles_formats():
    p = es.parse_cert_date
    assert p('2026-09-01').year == 2026                  # ISO date
    assert p('2026-09-01T00:00:00').month == 9           # ISO datetime
    assert p('Aug  1 00:00:00 2026 GMT').year == 2026    # OpenSSL double-space + zone
    assert p('Aug 1 2026').day == 1                       # bare %b %d %Y
    assert p('') is None and p(None) is None
    assert p('whenever') is None                          # unparseable → degrade


def test_cert_expiry_classifies_against_injected_now():
    now = datetime(2026, 6, 16)
    c, detail, expired = es._cert_expiry(_with_cert(_report(), '2026-06-01'), now=now)
    assert c == 1 and expired and 'истёк' in detail
    c, detail, expired = es._cert_expiry(_with_cert(_report(), '2026-06-20'), now=now)
    assert c == 1 and not expired and 'истекает' in detail
    c, _, expired = es._cert_expiry(_with_cert(_report(), '2027-06-01'), now=now)
    assert c == 0 and not expired                         # comfortably valid
    assert es._cert_expiry(_report(), now=now) == (0, '', False)        # no phase
    assert es._cert_expiry(_with_cert(_report(), 'nope'), now=now) == (0, '', False)


def test_expired_cert_adds_weighted_factor_and_chip():
    past = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d')
    s = es.build_summary(_with_cert(_report(weak_cookies=1), past))   # base score 2
    factor = {f['factor']: f for f in s['risk_factors']}['TLS-сертификат истёк/истекает']
    assert factor['count'] == 1 and factor['weight'] == 2 and factor['points'] == 2
    assert s['risk_score'] == 2 + 2                       # base + amplifier
    assert s['metrics']['cert_expiry'] == 1 and s['metrics']['cert_expired'] == 1
    assert any(c['label'] == 'Cert expired' for c in es.headline(s)['chips'])


def test_expiring_cert_is_amplifier_not_clearcut():
    soon = (datetime.now() + timedelta(days=5)).strftime('%Y-%m-%d')
    s = es.build_summary(_with_cert(_report(), soon))
    assert s['metrics']['cert_expiry'] == 1 and s['metrics']['cert_expired'] == 0
    assert s['risk_score'] == 2                           # 1 × weight 2
    assert s['risk_level'] == 'Low'                       # amplifier — not escalated
    assert any(c['label'] == 'Cert expiring' for c in es.headline(s)['chips'])


def test_cert_expiry_absent_leaves_score_unchanged():
    base = es.build_summary(_report(weak_cookies=1))
    assert base['metrics']['cert_expiry'] == 0 and base['metrics']['cert_expired'] == 0
    assert 'TLS-сертификат истёк/истекает' not in {
        f['factor'] for f in base['risk_factors']}
    far = (datetime.now() + timedelta(days=200)).strftime('%Y-%m-%d')
    assert es.build_summary(_with_cert(_report(weak_cookies=1), far))['risk_score'] \
        == base['risk_score']


# ── F-R7: reopened-finding regression surcharge ───────────────────────────────

def _with_reopened(report, reopened=0):
    """Inject the per-scan reopened count the findings sync stamps on a report."""
    report.setdefault('findings', {})['reopened'] = reopened
    return report


def test_regression_adds_weighted_surcharge():
    r = _with_reopened(_report(weak_cookies=1), reopened=2)        # base score 2
    s = es.build_summary(r)
    factor = {f['factor']: f
              for f in s['risk_factors']}['Регрессия (переоткрытые находки)']
    assert factor['count'] == 2 and factor['weight'] == 2 and factor['points'] == 4
    assert s['risk_score'] == 2 + 2 * 2                            # base + surcharge
    assert s['metrics']['regressions'] == 2


def test_regression_absent_leaves_score_unchanged():
    base = es.build_summary(_report(weak_cookies=1))
    assert base['metrics']['regressions'] == 0
    assert 'Регрессия (переоткрытые находки)' not in {
        f['factor'] for f in base['risk_factors']}
    # a synced findings block with zero reopened also adds nothing
    assert es.build_summary(_with_reopened(_report(weak_cookies=1), 0))['risk_score'] \
        == base['risk_score']


def test_regression_is_amplifier_not_clearcut():
    s = es.build_summary(_with_reopened(_report(), reopened=1))
    assert s['risk_score'] == 2          # 1 × weight 2
    assert s['risk_level'] == 'Low'      # amplifier — not escalated


def test_regression_chip_in_headline():
    hl = es.headline(es.build_summary(_with_reopened(_report(), reopened=3)))
    assert any('regression' in c['label'] for c in hl['chips'])


# ── F-R3: risk-factor breakdown in the report ─────────────────────────────────

def test_render_html_includes_risk_breakdown():
    html = es.render_html(es.build_summary(_report(secrets=2, weak_cookies=1)))
    assert 'Из чего риск' in html
    # Secrets + weak cookie all ride the vuln factor now (2×High 5 + 1×Medium 2).
    assert 'Уязвимости' in html
    assert '+12' in html


def test_render_html_no_breakdown_when_clean():
    html = es.render_html(es.build_summary(_report()))
    assert 'Из чего риск' not in html


# ── CVE Intelligence metric (EPIC 3) — display only, not a score addend ──────

def _report_with_cve(summary, *, high=0):
    r = _report(high=high)
    r['phases']['osv'] = {'data': {'cve_summary': summary}}
    return r


def test_cve_summary_is_metric_not_score_addend():
    # CVEs fold into vulns as findings (counted once via severity); the cve_summary
    # is a display metric and must add NO points to the risk score.
    base = es.build_summary(_report(high=1))
    s = es.build_summary(_report_with_cve(
        {'total': 3, 'high': 2, 'medium': 1, 'info': 0}, high=1))
    assert s['metrics']['cve_total'] == 3
    assert s['metrics']['cve_high'] == 2 and s['metrics']['cve_medium'] == 1
    assert s['risk_score'] == base['risk_score']          # no double count


def test_cve_headline_chip_present_and_tiered():
    s = es.build_summary(_report_with_cve({'total': 4, 'high': 1, 'medium': 3,
                                           'info': 0}))
    chip = next(c for c in es.headline(s)['chips'] if c['label'] == '4 CVE')
    assert chip['severity'] == 'high'                     # a High CVE present
    s2 = es.build_summary(_report_with_cve({'total': 2, 'high': 0, 'medium': 2,
                                            'info': 0}))
    chip2 = next(c for c in es.headline(s2)['chips'] if c['label'] == '2 CVE')
    assert chip2['severity'] == 'medium'                  # no High → medium chip


def test_cve_metric_zero_without_phase():
    s = es.build_summary(_report())
    assert s['metrics']['cve_total'] == 0
    assert all(c['label'] != '0 CVE' for c in es.headline(s)['chips'])


# ── Asset exposure clusters metric (EPIC 5) — display only, not a score addend ──

def test_exposure_clusters_metric_and_chip():
    r = _report(high=0)
    r['asset_graph'] = {'summary': {'nodes': 9, 'edges': 12, 'clusters': 2,
                                    'largest_cluster': 3}}
    base = es.build_summary(_report(high=0))
    s = es.build_summary(r)
    assert s['metrics']['exposure_clusters'] == 2
    assert s['metrics']['exposure_largest'] == 3
    assert s['risk_score'] == base['risk_score']          # display only, no points
    chips = [c['label'] for c in es.headline(s)['chips']]
    assert '2× co-hosted' in chips


def test_exposure_clusters_zero_without_graph():
    s = es.build_summary(_report())
    assert s['metrics']['exposure_clusters'] == 0
    assert all('co-hosted' not in c['label'] for c in es.headline(s)['chips'])


# ── Core Intelligence metric (EPIC 7) — display only ──────────────────────────

def test_intelligence_metric_from_report():
    r = _report()
    r['intelligence'] = {'summary': {'findings': 5, 'top_priority': 72,
                                     'high_confidence': 3}}
    s = es.build_summary(r)
    assert s['metrics']['top_priority'] == 72
    assert s['metrics']['high_confidence_findings'] == 3


def test_intelligence_metric_zero_without_layer():
    s = es.build_summary(_report())
    assert s['metrics']['top_priority'] == 0
    assert s['metrics']['high_confidence_findings'] == 0


# ── Asset Criticality metric (EPIC 9) — display only ──────────────────────────

def test_asset_criticality_metric_and_chip():
    r = _report(high=0)
    r['asset_criticality'] = {'summary': {'assets': 12, 'high_criticality': 3,
                                          'top_criticality': 82}}
    base = es.build_summary(_report(high=0))
    s = es.build_summary(r)
    assert s['metrics']['critical_assets'] == 3
    assert s['metrics']['top_asset_criticality'] == 82
    assert s['risk_score'] == base['risk_score']          # display only, no points
    chips = [c['label'] for c in es.headline(s)['chips']]
    assert '3 critical assets' in chips


def test_asset_criticality_metric_zero_without_engine():
    s = es.build_summary(_report())
    assert s['metrics']['critical_assets'] == 0
    assert all('critical asset' not in c['label'] for c in es.headline(s)['chips'])
