"""Offline tests for Authorized Network Execution Profiles (Roadmap E3)."""

import pytest

from core.audit_schema import validate_audit_payload
from core.execution_profile import (
    create_execution_profile,
    enforce_target_ip,
    execution_profile_summary,
    execution_profile_to_json,
    ip_authorized,
    normalize_execution_profile,
    profile_expired,
    validate_execution_profile,
)


_LEGAL = {
    "authorized_by": "Jane Client (CISO)",
    "reference": "AUTH-2026-014",
    "contract_id": "MSA-88",
    "valid_from": "2026-07-01",
    "valid_until": "2026-07-31",
    "notes": "Q3 external assessment",
}


def _profile(**over):
    base = dict(
        allowed_ips=["203.0.113.0/24", "198.51.100.7"],
        denied_ips=["203.0.113.5"],
        source_nodes=["'tester-vpn' 192.0.2.10"],
        legal=_LEGAL,
    )
    base.update(over)
    return create_execution_profile("q3-external", **base)


# --- normalize / create ------------------------------------------------------

def test_create_normalizes_cidr_and_ids():
    p = _profile()
    assert p["profile_id"].startswith("exec-")
    assert p["profile"] == "client_safe"
    assert "203.0.113.0/24" in p["allowed_ips"]
    assert "198.51.100.7" in p["allowed_ips"]
    assert p["legal"]["reference"] == "AUTH-2026-014"


def test_create_requires_name():
    with pytest.raises(ValueError):
        create_execution_profile("   ")


def test_normalize_drops_invalid_ips_and_dedups():
    p = normalize_execution_profile({
        "name": "x",
        "allowed_ips": ["10.0.0.0/8", "not-an-ip", "10.0.0.0/8", ""],
    })
    assert p["allowed_ips"] == ["10.0.0.0/8"]


def test_cidr_host_bits_are_normalized():
    p = normalize_execution_profile({"name": "x", "allowed_ips": ["10.1.2.3/24"]})
    assert p["allowed_ips"] == ["10.1.2.0/24"]


def test_normalize_tolerates_garbage():
    p = normalize_execution_profile(None)
    assert p["allowed_ips"] == [] and p["legal"]["authorized_by"] == ""


# --- validation --------------------------------------------------------------

def test_valid_profile_passes():
    result = validate_execution_profile(_profile())
    assert result["valid"] is True
    assert result["errors"] == []


def test_empty_allowlist_is_invalid():
    result = validate_execution_profile(create_execution_profile("x", legal=_LEGAL))
    assert result["valid"] is False
    assert any("allowed_ips is empty" in e for e in result["errors"])


def test_missing_legal_is_invalid():
    result = validate_execution_profile(
        create_execution_profile("x", allowed_ips=["10.0.0.0/8"]))
    assert result["valid"] is False
    assert any("authorized_by" in e for e in result["errors"])
    assert any("reference" in e for e in result["errors"])


def test_malformed_ip_reported_by_validate():
    result = validate_execution_profile(
        {"name": "x", "allowed_ips": ["10.0.0.0/8", "bogus"], "legal": _LEGAL})
    assert result["valid"] is False
    assert any("malformed" in e for e in result["errors"])


# --- ip_authorized (default-deny allowlist) ----------------------------------

def test_ip_within_allowlist_is_authorized():
    assert ip_authorized("203.0.113.9", _profile())["allowed"] is True


def test_denied_ip_wins_over_allowlist():
    # 203.0.113.5 is inside the /24 allowlist but explicitly denied.
    res = ip_authorized("203.0.113.5", _profile())
    assert res["allowed"] is False
    assert "denied" in res["reason"]


def test_ip_outside_allowlist_is_denied():
    res = ip_authorized("8.8.8.8", _profile())
    assert res["allowed"] is False
    assert "outside" in res["reason"]


def test_empty_allowlist_denies_everything():
    res = ip_authorized("8.8.8.8", create_execution_profile("x", legal=_LEGAL))
    assert res["allowed"] is False
    assert "default-deny" in res["reason"]


def test_malformed_target_is_denied():
    assert ip_authorized("not-an-ip", _profile())["allowed"] is False


def test_single_host_allow_entry():
    assert ip_authorized("198.51.100.7", _profile())["allowed"] is True
    assert ip_authorized("198.51.100.8", _profile())["allowed"] is False


# --- expiry ------------------------------------------------------------------

def test_profile_expired_by_window():
    p = _profile()
    assert profile_expired(p, now="2026-07-15") is False
    assert profile_expired(p, now="2026-08-01") is True


def test_no_valid_until_never_expires():
    legal = {**_LEGAL, "valid_until": ""}
    assert profile_expired(_profile(legal=legal), now="2099-01-01") is False


# --- enforce_target_ip (scan-time gate, E3 inc-2) ----------------------------

def test_enforce_off_is_noop_allow():
    res = enforce_target_ip("8.8.8.8", _profile(), now="2026-07-15", enabled=False)
    assert res == {"allowed": True,
                   "reason": "execution-profile enforcement is off",
                   "enforced": False}


def test_enforce_without_profile_is_noop_allow():
    res = enforce_target_ip("8.8.8.8", {}, now="2026-07-15", enabled=True)
    assert res["allowed"] is True and res["enforced"] is False


def test_enforce_allows_authorized_ip():
    res = enforce_target_ip("203.0.113.9", _profile(), now="2026-07-15")
    assert res["allowed"] is True and res["enforced"] is True


def test_enforce_denies_ip_outside_profile():
    res = enforce_target_ip("8.8.8.8", _profile(), now="2026-07-15")
    assert res["allowed"] is False and res["enforced"] is True
    assert "outside" in res["reason"]


def test_enforce_denies_when_window_expired():
    # Authorized IP, but the authorization window has lapsed → expiry denies first.
    res = enforce_target_ip("203.0.113.9", _profile(), now="2026-08-05")
    assert res["allowed"] is False and res["enforced"] is True
    assert "expired" in res["reason"]


# --- summary + schema --------------------------------------------------------

def test_summary_is_readable():
    s = execution_profile_summary(_profile())
    assert "allowed=" in s and "authorized_by=" in s


def test_to_json_is_schema_valid():
    payload = execution_profile_to_json(_profile())
    # Must not raise: the export conforms to the ASA execution-profile schema.
    validate_audit_payload(payload, "asa_execution_profile")
