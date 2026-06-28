"""Tests for the cookie security parser/scorer (network-free)."""

from core.cookie_auditor import (
    CookieFileError, describe_cookies_txt, read_cookies_txt, validate_cookies_txt,
    _parse_set_cookie, _score_cookie,
)


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


def test_cookies_txt_validation_masks_values(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.com\tTRUE\t/\tTRUE\t1893456000\tsid\tSUPERSECRETSESSION\n",
        encoding="utf-8",
    )

    result = validate_cookies_txt(str(path))

    assert result["status"] == "Success"
    assert result["total"] == 1
    assert result["domains"] == ["example.com"]
    cookie = result["cookies"][0]
    assert cookie["name"] == "sid"
    assert cookie["value_masked"] == "SUPE...len=18"
    assert "SUPERSECRETSESSION" not in repr(result)
    assert describe_cookies_txt(str(path)) == "1 cookie(s) for example.com"


def test_cookies_txt_accepts_httponly_prefix(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text(
        "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t0\tsid\tSECRET_VALUE\n",
        encoding="utf-8",
    )

    result = validate_cookies_txt(str(path))

    assert result["status"] == "Success"
    assert result["cookies"][0]["domain"] == ".example.com"
    assert result["cookies"][0]["http_only"] is True
    assert "SECRET_VALUE" not in repr(result)


def test_cookies_txt_reports_format_error_without_secret(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text("example.com\tbad\tline\tSECRET_VALUE\n", encoding="utf-8")

    result = validate_cookies_txt(str(path))

    assert result["status"] == "Error"
    assert "line 1" in result["error"]
    assert "7 tab-separated columns" in result["error"]
    assert "SECRET_VALUE" not in result["error"]


def test_cookies_txt_missing_file_is_clear(tmp_path):
    missing = tmp_path / "missing-cookies.txt"
    result = validate_cookies_txt(str(missing))
    assert result["status"] == "Error"
    assert "not found" in result["error"]


def test_cookies_txt_empty_raises_for_direct_reader(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text("# Netscape HTTP Cookie File\n", encoding="utf-8")
    try:
        read_cookies_txt(str(path))
    except CookieFileError as exc:
        assert "does not contain" in str(exc)
    else:
        raise AssertionError("expected CookieFileError")
