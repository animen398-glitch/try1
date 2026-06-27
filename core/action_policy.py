"""Client-safe action policy.

The default profile allows evidence collection and non-destructive checks only.
Destructive, brute-force, stealth, exploit, and payload execution actions are
blocked by class rather than by tool name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


CLIENT_SAFE_ALLOWED = {
    "headers_check",
    "cookie_flags_check",
    "tls_config_check",
    "source_map_detection",
    "graphql_introspection_detection",
    "dependency_cve_correlation",
    "non_destructive_endpoint_probe",
    "safe_active_probe",
    "iac_local_config_check",
}

CLIENT_SAFE_FORBIDDEN_KEYWORDS = (
    "destructive",
    "delete",
    "bruteforce",
    "brute_force",
    "credential",
    "stealth",
    "evasion",
    "exploit",
    "payload",
    "auto_login",
    "auth_bypass",
    "persistence",
)


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    action: str
    profile: str = "client_safe"
    reason: str = ""

    def as_dict(self) -> Dict[str, str | bool]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "profile": self.profile,
            "reason": self.reason,
        }


def evaluate_action_policy(action: str, *, profile: str = "client_safe") -> ActionDecision:
    clean_action = str(action or "").strip().lower()
    clean_profile = str(profile or "client_safe").strip().lower()
    if not clean_action:
        return ActionDecision(False, clean_action, clean_profile, "action is required")
    if clean_profile != "client_safe":
        return ActionDecision(False, clean_action, clean_profile, "unknown policy profile")
    if clean_action in CLIENT_SAFE_ALLOWED:
        return ActionDecision(True, clean_action, clean_profile)
    for keyword in CLIENT_SAFE_FORBIDDEN_KEYWORDS:
        if keyword in clean_action:
            return ActionDecision(
                False,
                clean_action,
                clean_profile,
                f"action class is forbidden in {clean_profile}: {keyword}",
            )
    return ActionDecision(False, clean_action, clean_profile, "action is not client_safe")


def check_action_policy(action: str, *, profile: str = "client_safe") -> ActionDecision:
    return evaluate_action_policy(action, profile=profile)


def is_action_allowed(action: str, *, profile: str = "client_safe") -> ActionDecision:
    return evaluate_action_policy(action, profile=profile)
