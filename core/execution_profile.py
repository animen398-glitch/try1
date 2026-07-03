"""Authorized Network Execution Profiles (Roadmap E3).

A pure, offline contract declaring the **network boundaries and legal basis** for
an authorized engagement, complementing the domain/action Rules of Engagement
(:mod:`core.audit_scope`) with the IP dimension it lacks:

- ``allowed_ips`` / ``denied_ips`` — the target IP ranges the engagement is
  authorized (or explicitly forbidden) to touch, as validated IP/CIDR entries.
- ``source_nodes`` — the declared origin addresses testing traffic runs *from*,
  so the client can allowlist the tester and the run stays auditable.
- ``legal`` — the authorization paper trail (who authorized it, the reference /
  contract id, and the validity window).

This module stores no state and performs no I/O or network calls; it only shapes,
validates and answers questions about an execution profile so other layers
(scope enforcement, a store, the GUI) can persist or consult it. It never widens
what is allowed — an empty allowlist authorizes nothing (default-deny).
"""

from __future__ import annotations

import ipaddress
from hashlib import sha1
from typing import Any, Dict, List, Optional


PROFILE = "client_safe"

_LEGAL_FIELDS = ("authorized_by", "reference", "contract_id", "valid_from",
                 "valid_until", "notes")


def _stable_id(name: str) -> str:
    return f"exec-{sha1(name.encode('utf-8')).hexdigest()[:16]}"


def _clean(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _norm_network(value: Any) -> Optional[str]:
    """Canonical string for a valid IP or CIDR, else ``None``.

    A bare IP is kept as-is (``203.0.113.5``); a CIDR is normalized to its
    network address (``203.0.113.0/24``). Host bits in a CIDR are tolerated
    (``strict=False``) and dropped.
    """
    text = _clean(value)
    if not text:
        return None
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _norm_network_list(values: Any) -> List[str]:
    out: List[str] = []
    for item in values or []:
        norm = _norm_network(item)
        if norm and norm not in out:
            out.append(norm)
    return out


def _norm_str_list(values: Any) -> List[str]:
    out: List[str] = []
    for item in values or []:
        text = _clean(item)
        if text and text not in out:
            out.append(text)
    return out


def _norm_legal(legal: Any) -> Dict[str, str]:
    src = legal if isinstance(legal, dict) else {}
    return {field: _clean(src.get(field)) for field in _LEGAL_FIELDS}


def normalize_execution_profile(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a canonical, JSON-serializable execution-profile dict.

    Invalid IP/CIDR entries are dropped (not fatal); every other field is
    coerced to its declared shape so the result is schema-clean.
    """
    src = profile if isinstance(profile, dict) else {}
    name = _clean(src.get("name")) or "unnamed"
    return {
        "profile_id": _clean(src.get("profile_id")) or _stable_id(name),
        "name": name,
        "label": _clean(src.get("label")),
        "profile": PROFILE,
        "allowed_ips": _norm_network_list(src.get("allowed_ips")),
        "denied_ips": _norm_network_list(src.get("denied_ips")),
        "source_nodes": _norm_str_list(src.get("source_nodes")),
        "legal": _norm_legal(src.get("legal")),
    }


def create_execution_profile(
    name: str,
    *,
    allowed_ips: Optional[List[str]] = None,
    denied_ips: Optional[List[str]] = None,
    source_nodes: Optional[List[str]] = None,
    legal: Optional[Dict[str, Any]] = None,
    label: str = "",
) -> Dict[str, Any]:
    """Build a normalized execution profile. ``name`` is required."""
    clean_name = _clean(name)
    if not clean_name:
        raise ValueError("execution profile name is required")
    return normalize_execution_profile({
        "name": clean_name,
        "label": label,
        "allowed_ips": allowed_ips,
        "denied_ips": denied_ips,
        "source_nodes": source_nodes,
        "legal": legal,
    })


def _has_invalid(values: Any) -> bool:
    for item in values or []:
        if _clean(item) and _norm_network(item) is None:
            return True
    return False


def validate_execution_profile(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Check completeness/consistency for an *authorized* profile.

    Returns ``{valid, errors, profile}``. Errors: a malformed IP/CIDR was
    supplied, no ``allowed_ips`` (an allowlist that authorizes nothing), or a
    missing legal ``authorized_by`` / ``reference``. Normalization itself never
    fails — this is the gate a caller runs before treating a profile as binding.
    """
    src = profile if isinstance(profile, dict) else {}
    errors: List[str] = []
    if _has_invalid(src.get("allowed_ips")):
        errors.append("allowed_ips contains a malformed IP/CIDR")
    if _has_invalid(src.get("denied_ips")):
        errors.append("denied_ips contains a malformed IP/CIDR")

    normalized = normalize_execution_profile(src)
    if not normalized["allowed_ips"]:
        errors.append("allowed_ips is empty (an execution profile must authorize "
                      "at least one IP/range)")
    if not normalized["legal"]["authorized_by"]:
        errors.append("legal.authorized_by is required")
    if not normalized["legal"]["reference"]:
        errors.append("legal.reference is required")
    return {"valid": not errors, "errors": errors, "profile": normalized}


def _in_any(ip_obj, networks: List[str]) -> bool:
    for net in networks:
        try:
            if ip_obj in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def ip_authorized(ip: str, profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Whether a target ``ip`` is authorized by this profile (default-deny).

    Returns ``{allowed, reason}``. An explicit ``denied_ips`` match wins; then
    membership in ``allowed_ips`` allows; anything else is denied. A profile with
    no ``allowed_ips`` authorizes nothing. A malformed ``ip`` is denied.
    """
    normalized = normalize_execution_profile(profile)
    try:
        ip_obj = ipaddress.ip_address(_clean(ip))
    except ValueError:
        return {"allowed": False, "reason": "target is not a valid IP"}
    if _in_any(ip_obj, normalized["denied_ips"]):
        return {"allowed": False, "reason": "target is in denied_ips"}
    if not normalized["allowed_ips"]:
        return {"allowed": False, "reason": "no allowed_ips declared (default-deny)"}
    if _in_any(ip_obj, normalized["allowed_ips"]):
        return {"allowed": True, "reason": "target is within allowed_ips"}
    return {"allowed": False, "reason": "target is outside allowed_ips"}


def profile_expired(profile: Optional[Dict[str, Any]], *, now: str) -> bool:
    """Whether the authorization window has lapsed.

    Compares ISO-8601 ``now`` (``YYYY-MM-DD`` or a full timestamp) to
    ``legal.valid_until`` as strings — an unset ``valid_until`` never expires.
    String compare is safe because ISO-8601 is lexicographically ordered.
    """
    normalized = normalize_execution_profile(profile)
    valid_until = normalized["legal"]["valid_until"]
    if not valid_until:
        return False
    return _clean(now) > valid_until


def enforce_target_ip(
    ip: str,
    profile: Optional[Dict[str, Any]],
    *,
    now: str,
    enabled: bool = True,
) -> Dict[str, Any]:
    """Scan-time gate for a resolved target IP (Roadmap E3 increment 2).

    Answers, in one call, the two questions a run must resolve before touching a
    resolved target IP: is the engagement's authorization window still valid, and
    is this IP inside the declared boundary? Returns ``{allowed, reason,
    enforced}``.

    Enforcement is **strictly opt-in**: when ``enabled`` is false or no profile is
    configured, ``enforced`` is ``False`` and ``allowed`` is ``True`` — an
    unconfigured run behaves exactly as before (the profile's default-deny is
    *not* imposed on users who never declared one). When ``enabled`` and a profile
    is present, an expired authorization window denies first, then
    :func:`ip_authorized` decides (default-deny *within* the profile).
    """
    if not enabled or not profile:
        return {"allowed": True, "reason": "execution-profile enforcement is off",
                "enforced": False}
    if profile_expired(profile, now=now):
        return {"allowed": False, "reason": "authorization window has expired",
                "enforced": True}
    decision = ip_authorized(ip, profile)
    return {"allowed": decision["allowed"], "reason": decision["reason"],
            "enforced": True}


def execution_profile_summary(profile: Optional[Dict[str, Any]]) -> str:
    n = normalize_execution_profile(profile)
    allowed = ", ".join(n["allowed_ips"]) or "none"
    denied = ", ".join(n["denied_ips"]) or "none"
    sources = ", ".join(n["source_nodes"]) or "none"
    auth = n["legal"]["authorized_by"] or "unauthorized"
    return (f"profile={n['profile']} | allowed={allowed} | denied={denied} | "
            f"sources={sources} | authorized_by={auth}")


def execution_profile_to_json(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical schema-valid export of an execution profile."""
    return normalize_execution_profile(profile)
