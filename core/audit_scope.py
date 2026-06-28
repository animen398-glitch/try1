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


# ROE/scope templates (Workbench v2 F2). Each template is a partial ROE merged
# onto DEFAULT_ROE; the operator still fills authorization fields. Active
# templates only enable *safe active checks* — never credential or exploit work.
ROE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "passive_external": {
        "label": "Passive External",
        "description": "Passive-only recon against an external target.",
        "active_scan_enabled": False,
        "passive_only": True,
        "rate_limit": "1/s",
    },
    "authenticated_internal": {
        "label": "Authenticated Internal",
        "description": (
            "Safe active checks with an operator-supplied authorized session. "
            "Requires allowed_domains and authorized_by; no credential work."
        ),
        "active_scan_enabled": True,
        "passive_only": False,
        "rate_limit": "1/s",
    },
    "evidence_only": {
        "label": "Evidence Only",
        "description": "Passive re-check of existing findings and their evidence.",
        "active_scan_enabled": False,
        "passive_only": True,
        "rate_limit": None,
    },
    "release_gate": {
        "label": "Release Gate",
        "description": "Passive pre-release comparison against a baseline run.",
        "active_scan_enabled": False,
        "passive_only": True,
        "rate_limit": None,
    },
}


def list_roe_templates() -> list[Dict[str, Any]]:
    """Return all ROE templates as a stable, name-sorted list of copies."""
    out: list[Dict[str, Any]] = []
    for name in sorted(ROE_TEMPLATES):
        tpl = dict(ROE_TEMPLATES[name])
        tpl["name"] = name
        out.append(tpl)
    return out


def roe_template(name: str) -> Dict[str, Any]:
    """Return one ROE template (copy, with ``name``); raise on unknown."""
    key = str(name or "").strip()
    if key not in ROE_TEMPLATES:
        raise ValueError(f"unknown ROE template: {key}")
    tpl = dict(ROE_TEMPLATES[key])
    tpl["name"] = key
    return tpl


def apply_roe_template(
    name: str,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolve a ROE template into a normalized ROE dict.

    ``overrides`` (e.g. allowed_domains, authorized_by) win over the template;
    the result is normalized but not asserted valid — callers use
    :func:`validate_roe` when authorization completeness matters.
    """
    tpl = roe_template(name)
    merged = {key: value for key, value in tpl.items() if key != "name"}
    merged.pop("label", None)
    merged.pop("description", None)
    if isinstance(overrides, dict):
        merged.update(overrides)
    return normalize_roe(merged)


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
        f"profile={normalized['profile']} | {mode} | "
        f"allowed={allowed} | denied={denied} | rate={rate}"
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
