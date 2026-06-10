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
