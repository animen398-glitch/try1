"""Rules of Engagement helpers for Client-Safe Pentest Workbench."""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.scope_guard import normalize_scope
from core.scope_policy import evaluate_scope_policy


DEFAULT_ROE: Dict[str, Any] = {
    "profile": "client_safe",
    "allowed_domains": [],
    "denied_domains": [],
    "forbidden_paths": [],
    "active_scan_enabled": False,
    "passive_only": True,
    "rate_limit": None,
    "authorized_by": "",
    "expires_at": "",
}


def normalize_roe(roe: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    src = roe if isinstance(roe, dict) else {}
    scope = normalize_scope({**DEFAULT_ROE, **src})
    out = dict(DEFAULT_ROE)
    out.update(scope)
    out["profile"] = str(src.get("profile") or DEFAULT_ROE["profile"]).strip().lower()
    out["forbidden_paths"] = [
        str(path).strip()
        for path in (src.get("forbidden_paths") or [])
        if str(path).strip()
    ]
    out["authorized_by"] = str(src.get("authorized_by") or "").strip()
    out["expires_at"] = str(src.get("expires_at") or "").strip()
    return out


def validate_roe(roe: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    normalized = normalize_roe(roe)
    errors: list[str] = []
    if normalized["profile"] != "client_safe":
        errors.append("profile must be client_safe")
    if normalized["active_scan_enabled"] and not normalized["allowed_domains"]:
        errors.append("active checks require allowed_domains")
    if normalized["active_scan_enabled"] and normalized["passive_only"]:
        errors.append("active_scan_enabled conflicts with passive_only")
    return {"valid": not errors, "errors": errors, "roe": normalized}


def roe_summary(roe: Optional[Dict[str, Any]]) -> str:
    normalized = normalize_roe(roe)
    mode = "passive-only" if normalized["passive_only"] else "active allowed"
    allowed = ", ".join(normalized["allowed_domains"]) or "none"
    denied = ", ".join(normalized["denied_domains"]) or "none"
    rate = normalized["rate_limit"] or "unset"
    return (
        f"profile={normalized['profile']} · {mode} · "
        f"allowed={allowed} · denied={denied} · rate={rate}"
    )


def roe_allows_action(
    action: str,
    target: str,
    roe: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    normalized = normalize_roe(roe)
    decision = evaluate_scope_policy(
        action,
        target,
        normalized,
        profile=normalized["profile"],
    )
    return decision.as_dict()
