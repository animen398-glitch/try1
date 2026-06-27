"""Scope and ROE policy for client-safe audit actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from core.action_policy import evaluate_action_policy
from core.scope_guard import active_phase_decision, host_from_url, normalize_scope


@dataclass(frozen=True)
class ScopePolicyDecision:
    allowed: bool
    action: str
    target: str
    profile: str = "client_safe"
    host: str = ""
    reason: str = ""

    def as_dict(self) -> Dict[str, str | bool]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "target": self.target,
            "profile": self.profile,
            "host": self.host,
            "reason": self.reason,
        }


def _path_from_target(target: str) -> str:
    parsed = urlparse(str(target or ""))
    return parsed.path or "/"


def _forbidden_path_reason(target: str, scope: Dict[str, Any]) -> str:
    path = _path_from_target(target)
    for raw in scope.get("forbidden_paths") or []:
        forbidden = str(raw or "").strip()
        if forbidden and path.startswith(forbidden):
            return f"path {path} denied by {forbidden}"
    return ""


def evaluate_scope_policy(
    action: str,
    target: str,
    scope: Optional[Dict[str, Any]],
    *,
    profile: str = "client_safe",
) -> ScopePolicyDecision:
    clean_action = str(action or "").strip().lower()
    clean_target = str(target or "").strip()
    clean_profile = str(profile or "client_safe").strip().lower()
    normalized = normalize_scope(scope)
    if isinstance(scope, dict) and "forbidden_paths" in scope:
        normalized["forbidden_paths"] = list(scope.get("forbidden_paths") or [])
    host = host_from_url(clean_target)

    action_decision = evaluate_action_policy(clean_action, profile=clean_profile)
    if not action_decision.allowed:
        return ScopePolicyDecision(
            False,
            clean_action,
            clean_target,
            clean_profile,
            host,
            action_decision.reason,
        )

    denied_path = _forbidden_path_reason(clean_target, normalized)
    if denied_path:
        return ScopePolicyDecision(
            False, clean_action, clean_target, clean_profile, host, denied_path
        )

    decision = active_phase_decision(clean_action, clean_target, normalized)
    if not decision.allowed:
        return ScopePolicyDecision(
            False,
            clean_action,
            clean_target,
            clean_profile,
            decision.host,
            decision.reason,
        )
    return ScopePolicyDecision(True, clean_action, clean_target, clean_profile, host)


def check_scope_policy(
    action: str,
    target: str,
    scope: Optional[Dict[str, Any]],
    *,
    profile: str = "client_safe",
) -> ScopePolicyDecision:
    return evaluate_scope_policy(action, target, scope, profile=profile)
