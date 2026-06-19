"""Project-level scope rules for active collection phases.

Scope Guard v1 is intentionally small and offline: it answers only whether an
active phase may run for the current project target. It stores no state, opens no
network connection, and treats ``rate_limit`` as metadata for operators/runners
that may enforce it later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse


DEFAULT_SCOPE: Dict[str, Any] = {
    "allowed_domains": [],
    "denied_domains": [],
    "active_scan_enabled": True,
    "passive_only": False,
    "rate_limit": None,
}

SAFE_DEFAULT_SCOPE: Dict[str, Any] = {
    "allowed_domains": [],
    "denied_domains": [],
    "active_scan_enabled": False,
    "passive_only": True,
    "rate_limit": None,
}


@dataclass(frozen=True)
class ScopeDecision:
    """A single allow/skip decision for a phase."""

    allowed: bool
    phase: str
    host: str
    reason: str = ""

    def as_dict(self) -> Dict[str, str | bool]:
        return {
            "allowed": self.allowed,
            "phase": self.phase,
            "host": self.host,
            "reason": self.reason,
        }


def host_from_url(url_or_host: str) -> str:
    """Lower-case host without port from a URL or bare host."""
    raw = (url_or_host or "").strip()
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        host = raw.split("/", 1)[0].split(":", 1)[0]
    return host.strip().lower().rstrip(".")


def normalize_domain_pattern(value: Any) -> str:
    """Canonical exact/wildcard domain pattern, or empty string if invalid."""
    pat = str(value or "").strip().lower().rstrip(".")
    if not pat:
        return ""
    if pat.startswith("http://") or pat.startswith("https://"):
        pat = host_from_url(pat)
    if pat.startswith("."):
        pat = f"*{pat}"
    return pat


def _normalize_patterns(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Iterable):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        pat = normalize_domain_pattern(value)
        if pat and pat not in seen:
            seen.add(pat)
            out.append(pat)
    return out


def normalize_scope(scope: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a backward-compatible, canonical Scope Guard config.

    Missing scope means legacy projects keep their previous behavior: active
    opt-in phases are allowed unless an explicit project scope says otherwise.
    """
    src = scope if isinstance(scope, dict) else {}
    out = dict(DEFAULT_SCOPE)
    out["allowed_domains"] = _normalize_patterns(src.get("allowed_domains"))
    out["denied_domains"] = _normalize_patterns(src.get("denied_domains"))
    out["active_scan_enabled"] = bool(
        src.get("active_scan_enabled", DEFAULT_SCOPE["active_scan_enabled"])
    )
    out["passive_only"] = bool(src.get("passive_only", DEFAULT_SCOPE["passive_only"]))
    out["rate_limit"] = src.get("rate_limit", DEFAULT_SCOPE["rate_limit"])
    return out


def default_scope_for_target(url_or_host: str = "") -> Dict[str, Any]:
    """Safe explicit scope for newly-created projects."""
    scope = dict(SAFE_DEFAULT_SCOPE)
    host = host_from_url(url_or_host)
    if host:
        scope["allowed_domains"] = [host]
    return normalize_scope(scope)


def domain_matches(host: str, pattern: str) -> bool:
    """Exact or ``*.example.com`` wildcard match."""
    host = host_from_url(host)
    pattern = normalize_domain_pattern(pattern)
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith(f".{suffix}") and host != suffix
    return host == pattern


def host_allowed(host: str, scope: Optional[Dict[str, Any]]) -> tuple[bool, str]:
    """Evaluate host against denied/allowed domains.

    Deny rules win. An empty allowlist is open for backward compatibility.
    """
    normalized = normalize_scope(scope)
    clean_host = host_from_url(host)
    for pattern in normalized["denied_domains"]:
        if domain_matches(clean_host, pattern):
            return False, f"host {clean_host} denied by {pattern}"
    allowed = normalized["allowed_domains"]
    if not allowed:
        return True, ""
    if any(domain_matches(clean_host, pattern) for pattern in allowed):
        return True, ""
    return False, f"host {clean_host} is outside allowed domains"


def active_phase_decision(
    phase: str,
    url_or_host: str,
    scope: Optional[Dict[str, Any]],
) -> ScopeDecision:
    """Allow/skip decision for an active phase."""
    normalized = normalize_scope(scope)
    host = host_from_url(url_or_host)
    ok, reason = host_allowed(host, normalized)
    if not ok:
        return ScopeDecision(False, phase, host, reason)
    if normalized["passive_only"]:
        return ScopeDecision(False, phase, host, "project is passive_only")
    if not normalized["active_scan_enabled"]:
        return ScopeDecision(False, phase, host, "active_scan_enabled is false")
    return ScopeDecision(True, phase, host)
