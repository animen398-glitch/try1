"""Deterministic executive summary — risk verdict, findings, recommendations.

All offline and model-free: pure functions over a collection ``report`` dict.
"""

from core import executive_summary as es


def _report(*, high=0, medium=0, info=0, risk_score=0, secrets=0,
            weak_cookies=0, status_summary=None, findings=None, cms=None):
    return {
        'phases': {
            'recon': {'data': {'cms': cms or []}},
            'api': {'data': {'keys_found': secrets}},
            'capture': {'data': {'pages_captured': 3,
                                 'status_summary': status_summary or {}}},
            'cookies': {'data': {'weak': weak_cookies}},
            'vulns': {
                'summary': {'high': high, 'medium': medium, 'info': info,
                            'risk_score': risk_score},
                'findings': findings or [],
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


def test_three_high_is_critical():
    s = es.build_summary(_report(high=3, risk_score=15))
    assert s['risk_level'] == 'Critical'


def test_single_high_is_high():
    s = es.build_summary(_report(high=1, risk_score=5))
    assert s['risk_level'] == 'High'


def test_medium_band():
    # weak cookies (2 each) push score into the Medium band without any high.
    s = es.build_summary(_report(weak_cookies=2))
    assert s['risk_score'] == 4
    assert s['risk_level'] == 'Medium'


def test_low_band():
    s = es.build_summary(_report(info=2, risk_score=2))
    assert s['risk_level'] == 'Low'


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
