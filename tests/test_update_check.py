"""Tests for core.update_check — opt-in, offline (transport injected)."""

import pytest

from core import update_check as uc


def test_parse_version_orders_numerically():
    assert uc.parse_version("1.2.3") == (1, 2, 3)
    assert uc.parse_version("v1.4.0-rc1") == (1, 4, 0, 1)
    assert uc.parse_version("") == (0,)
    assert uc.parse_version("2.0.0") > uc.parse_version("1.9.9")
    assert uc.parse_version("1.10.0") > uc.parse_version("1.9.0")


def test_update_available_when_endpoint_reports_newer():
    res = uc.check_for_update(current="1.0.0", endpoint="https://x/latest.json",
                              fetch=lambda e, t: {"version": "1.2.0",
                                                  "url": "https://x/dl"})
    assert res["status"] == "update_available"
    assert res["update_available"] is True
    assert res["latest"] == "1.2.0" and res["url"] == "https://x/dl"


def test_up_to_date_when_same_or_older():
    res = uc.check_for_update(current="2.0.0", endpoint="https://x/l",
                             fetch=lambda e, t: {"version": "2.0.0"})
    assert res["status"] == "up_to_date"
    assert res["update_available"] is False


def test_disabled_without_endpoint():
    res = uc.check_for_update(current="1.0.0", endpoint="")
    assert res == {"status": "disabled", "current": "1.0.0"}


def test_error_is_captured_not_raised():
    def boom(endpoint, timeout):
        raise OSError("network down")

    res = uc.check_for_update(current="1.0.0", endpoint="https://x/l", fetch=boom)
    assert res["status"] == "error" and "network down" in res["error"]


def test_error_on_response_without_version():
    res = uc.check_for_update(current="1.0.0", endpoint="https://x/l",
                             fetch=lambda e, t: {"url": "https://x/dl"})
    assert res["status"] == "error"


def test_fetch_rejects_non_https():
    with pytest.raises(ValueError, match="https"):
        uc._fetch("http://insecure/latest.json", 5.0)


def test_check_reads_settings_when_endpoint_omitted(monkeypatch):
    from core import config
    monkeypatch.setattr(config, "load_settings", lambda: {
        "update_check": {"enabled": True, "endpoint": "https://x/l"}})
    res = uc.check_for_update(current="1.0.0",
                              fetch=lambda e, t: {"version": "1.5.0"})
    assert res["status"] == "update_available"
    # Disabled setting → no network, disabled result.
    monkeypatch.setattr(config, "load_settings", lambda: {
        "update_check": {"enabled": False, "endpoint": "https://x/l"}})
    assert uc.check_for_update(current="1.0.0",
                               fetch=lambda e, t: {"version": "9"})["status"] == "disabled"


def test_update_line_formats_each_status():
    assert "1.2.0" in uc.update_line({"status": "update_available", "current": "1.0.0",
                                      "latest": "1.2.0", "url": "https://x"})
    assert "последняя" in uc.update_line({"status": "up_to_date", "current": "1.0.0"})
    assert "не удалась" in uc.update_line({"status": "error", "error": "x"})
    assert "отключена" in uc.update_line({"status": "disabled"})
