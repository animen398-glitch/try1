"""Tests for VulnScanner cookie findings and summarize() scoring."""

from core.vuln_scanner import (
    SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM, VulnScanner,
)


def test_scan_backward_compatible_without_cookies():
    findings = VulnScanner().scan({"url": "http://x"}, {})
    # plain-HTTP still flagged as High; no crash without cookie_result
    assert any(f["severity"] == SEVERITY_HIGH and "HTTP" in f["title"]
               for f in findings)


def test_cookie_samesite_none_without_secure_is_high():
    cookie_result = {
        "status": "Success",
        "cookies": [
            {"name": "csrf", "secure": False, "samesite": "None",
             "verdict": "Weak", "issues": ["SameSite=None without Secure"]},
        ],
    }
    findings = VulnScanner().scan({}, {}, cookie_result)
    cookie_findings = [f for f in findings if "csrf" in f["title"]]
    assert len(cookie_findings) == 1
    assert cookie_findings[0]["severity"] == SEVERITY_HIGH
    # Tagged with the canonical category so consumers (attack-surface graph)
    # can tell it apart without title sniffing.
    assert cookie_findings[0]["category"] == "cookie"


def test_cookie_weak_is_medium():
    cookie_result = {
        "status": "Success",
        "cookies": [
            {"name": "track", "secure": False, "samesite": "—",
             "verdict": "Weak", "issues": ["No HttpOnly", "No Secure"]},
        ],
    }
    findings = VulnScanner().scan({}, {}, cookie_result)
    weak = [f for f in findings if "track" in f["title"]]
    assert weak and weak[0]["severity"] == SEVERITY_MEDIUM
    assert weak[0]["category"] == "cookie"


def test_cookie_strong_produces_no_finding():
    cookie_result = {
        "status": "Success",
        "cookies": [
            {"name": "sid", "secure": True, "samesite": "Strict",
             "verdict": "Strong", "issues": []},
        ],
    }
    findings = VulnScanner().scan({}, {}, cookie_result)
    assert not any("sid" in f["title"] for f in findings)


def test_failed_cookie_result_ignored():
    findings = VulnScanner().scan({}, {}, {"status": "Error", "cookies": []})
    assert isinstance(findings, list)  # no crash, no cookie findings


def test_summarize_counts_and_score():
    findings = [
        {"severity": SEVERITY_HIGH},
        {"severity": SEVERITY_HIGH},
        {"severity": SEVERITY_MEDIUM},
        {"severity": SEVERITY_INFO},
        {"severity": "Bogus"},  # ignored
    ]
    s = VulnScanner.summarize(findings)
    assert s["high"] == 2 and s["medium"] == 1 and s["info"] == 1
    assert s["total"] == 4
    assert s["risk_score"] == 5 * 2 + 2 * 1 + 1 * 1  # 13


def test_summarize_empty():
    s = VulnScanner.summarize([])
    assert s == {"high": 0, "medium": 0, "info": 0, "total": 0, "risk_score": 0}


def _recon_with_headers(**security):
    return {"url": "https://x", "security_headers": security}


def test_csp_unsafe_inline_flagged():
    recon = _recon_with_headers(**{
        "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"
    })
    findings = VulnScanner().scan(recon, {})
    csp = [f for f in findings if f["title"] == "Weak Content-Security-Policy"]
    assert csp and csp[0]["severity"] == SEVERITY_MEDIUM
    assert "unsafe-inline" in csp[0]["detail"]


def test_csp_wildcard_source_flagged():
    recon = _recon_with_headers(**{"content-security-policy": "default-src *"})
    findings = VulnScanner().scan(recon, {})
    assert any(f["title"] == "Weak Content-Security-Policy" for f in findings)


def test_csp_strict_not_flagged():
    recon = _recon_with_headers(**{"content-security-policy": "default-src 'self'"})
    findings = VulnScanner().scan(recon, {})
    assert not any(f["title"] == "Weak Content-Security-Policy" for f in findings)


def test_csp_unsafe_inline_with_nonce_not_flagged():
    # CSP3: 'unsafe-inline' is ignored when a nonce/hash is present, so a modern
    # backward-compatible policy must NOT be reported as weak for unsafe-inline.
    recon = _recon_with_headers(**{
        "content-security-policy":
            "script-src 'nonce-rAnd0m==' 'unsafe-inline'; default-src 'self'"})
    findings = VulnScanner().scan(recon, {})
    assert not any(f["title"] == "Weak Content-Security-Policy" for f in findings)
    # A hash source grants the same exemption.
    recon2 = _recon_with_headers(**{
        "content-security-policy": "script-src 'sha256-abc123' 'unsafe-inline'"})
    assert not any(f["title"] == "Weak Content-Security-Policy"
                   for f in VulnScanner().scan(recon2, {}))


def test_csp_unsafe_inline_without_nonce_still_flagged():
    # No nonce/hash → 'unsafe-inline' is a genuine weakness (still flagged); and
    # 'unsafe-eval' is never exempted by a nonce.
    recon = _recon_with_headers(**{
        "content-security-policy": "script-src 'nonce-x' 'unsafe-eval'"})
    csp = [f for f in VulnScanner().scan(recon, {})
           if f["title"] == "Weak Content-Security-Policy"]
    assert csp and "unsafe-eval" in csp[0]["detail"]


def test_csp_frame_ancestors_satisfies_x_frame_options():
    # A site protecting against clickjacking with modern CSP frame-ancestors but no
    # legacy X-Frame-Options header must NOT be reported as missing X-Frame-Options.
    recon = _recon_with_headers(**{
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()"})
    findings = VulnScanner().scan(recon, {})
    missing = [f for f in findings if f["title"].startswith("Missing security headers")]
    assert not missing                    # all expected headers covered (XFO via CSP)


def test_missing_x_frame_options_without_frame_ancestors_still_flagged():
    # Without frame-ancestors (or the header), X-Frame-Options is genuinely missing.
    recon = _recon_with_headers(**{
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()"})
    findings = VulnScanner().scan(recon, {})
    missing = [f for f in findings if f["title"].startswith("Missing security headers")]
    assert missing and "x-frame-options" in missing[0]["detail"]


def test_hsts_short_max_age_flagged():
    recon = _recon_with_headers(**{"strict-transport-security": "max-age=3600"})
    findings = VulnScanner().scan(recon, {})
    hsts = [f for f in findings if f["title"] == "HSTS max-age too short"]
    assert hsts and hsts[0]["severity"] == SEVERITY_MEDIUM


def test_hsts_missing_include_subdomains_is_info():
    recon = _recon_with_headers(**{"strict-transport-security": "max-age=31536000"})
    findings = VulnScanner().scan(recon, {})
    assert any(f["title"] == "HSTS without includeSubDomains"
               and f["severity"] == SEVERITY_INFO for f in findings)


def test_hsts_strong_not_flagged():
    recon = _recon_with_headers(**{
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload"
    })
    findings = VulnScanner().scan(recon, {})
    assert not any("HSTS" in f["title"] for f in findings)


def test_weak_referrer_policy_flagged():
    recon = _recon_with_headers(**{"referrer-policy": "unsafe-url"})
    findings = VulnScanner().scan(recon, {})
    rp = [f for f in findings if f["title"] == "Weak Referrer-Policy"]
    assert rp and rp[0]["severity"] == SEVERITY_INFO


def test_strict_referrer_policy_not_flagged():
    recon = _recon_with_headers(**{"referrer-policy": "no-referrer"})
    findings = VulnScanner().scan(recon, {})
    assert not any(f["title"] == "Weak Referrer-Policy" for f in findings)


def test_weak_frame_options_flagged():
    recon = _recon_with_headers(**{"x-frame-options": "ALLOW-FROM https://x"})
    findings = VulnScanner().scan(recon, {})
    xfo = [f for f in findings if "X-Frame-Options" in f["title"]]
    assert xfo and xfo[0]["severity"] == SEVERITY_MEDIUM


def test_sameorigin_frame_options_not_flagged():
    recon = _recon_with_headers(**{"x-frame-options": "SAMEORIGIN"})
    findings = VulnScanner().scan(recon, {})
    assert not any("X-Frame-Options" in f["title"] for f in findings)
