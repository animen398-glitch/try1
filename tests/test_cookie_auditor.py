"""Tests for the cookie security parser/scorer (network-free)."""

from core.cookie_auditor import _parse_set_cookie, _score_cookie


def test_strong_cookie_all_flags():
    c = _parse_set_cookie("sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict")
    assert c["name"] == "sid"
    assert c["httponly"] and c["secure"]
    assert c["samesite"] == "Strict"
    assert c["score"] == 3
    assert c["verdict"] == "Strong"
    assert c["issues"] == []


def test_weak_cookie_no_flags():
    c = _parse_set_cookie("track=xyz; Path=/")
    assert (c["httponly"], c["secure"]) == (False, False)
    assert c["samesite"] == "—"
    assert c["score"] == 0
    assert c["verdict"] == "Weak"
    assert len(c["issues"]) == 3


def test_samesite_none_without_secure_flagged():
    c = _score_cookie("csrf", httponly=False, secure=False, samesite="None")
    assert c["verdict"] == "Weak"
    assert any("None" in issue for issue in c["issues"])


def test_samesite_lax_is_safe_case_insensitive():
    c = _score_cookie("s", httponly=True, secure=True, samesite="lax")
    assert c["score"] == 3
    assert c["verdict"] == "Strong"


def test_moderate_two_of_three():
    c = _score_cookie("m", httponly=True, secure=False, samesite="Lax")
    assert c["score"] == 2
    assert c["verdict"] == "Moderate"
    assert len(c["issues"]) == 1


def test_empty_line_parses_to_empty():
    assert _parse_set_cookie("   ") == {}
