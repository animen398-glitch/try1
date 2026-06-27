import importlib

import pytest


def _scope_decision_for(action, target, scope, *, profile="client_safe"):
    module = importlib.import_module("core.scope_policy")
    candidates = (
        "evaluate_scope_policy",
        "check_scope_policy",
        "check_scope",
        "is_in_scope",
        "active_check_decision",
    )
    for name in candidates:
        func = getattr(module, name, None)
        if callable(func):
            return func(action=action, target=target, scope=scope, profile=profile)
    pytest.fail(
        "core.scope_policy needs a public scope decision function accepting "
        "action, target, scope, and profile"
    )


def _allowed(decision):
    if isinstance(decision, bool):
        return decision
    if isinstance(decision, dict):
        return bool(decision.get("allowed"))
    return bool(getattr(decision, "allowed"))


def _reason(decision):
    if isinstance(decision, dict):
        return str(decision.get("reason", ""))
    return str(getattr(decision, "reason", ""))


@pytest.mark.parametrize(
    ("target", "action"),
    [
        ("https://evil.example.net/admin", "safe_active_probe"),
        ("https://api.example.com/forbidden/health", "safe_active_probe"),
    ],
)
def test_scope_policy_blocks_out_of_scope_active_checks(target, action):
    decision = _scope_decision_for(
        action,
        target,
        {
            "allowed_domains": ["example.com", "*.example.com"],
            "denied_domains": ["evil.example.net"],
            "forbidden_paths": ["/forbidden"],
            "active_scan_enabled": True,
            "passive_only": False,
        },
    )

    assert _allowed(decision) is False
    assert _reason(decision)


def test_scope_policy_blocks_active_checks_when_profile_is_passive_only():
    decision = _scope_decision_for(
        "safe_active_probe",
        "https://example.com/health",
        {
            "allowed_domains": ["example.com"],
            "active_scan_enabled": False,
            "passive_only": True,
        },
    )

    assert _allowed(decision) is False
    assert "active" in _reason(decision).lower() or "passive" in _reason(decision).lower()
