import importlib

import pytest


def _action_decision(action, *, profile="client_safe"):
    module = importlib.import_module("core.action_policy")
    candidates = (
        "evaluate_action_policy",
        "check_action_policy",
        "is_action_allowed",
        "action_allowed",
        "decision_for_action",
    )
    for name in candidates:
        func = getattr(module, name, None)
        if callable(func):
            return func(action, profile=profile)
    pytest.fail(
        "core.action_policy needs a public action decision function accepting "
        "an action and profile"
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
    "action",
    [
        "destructive_delete",
        "bruteforce_login",
        "stealth_evasion",
        "exploit_execution",
        "payload_execution",
    ],
)
def test_client_safe_blocks_forbidden_action_classes(action):
    decision = _action_decision(action, profile="client_safe")

    assert _allowed(decision) is False
    assert _reason(decision)


@pytest.mark.parametrize(
    "action",
    [
        "headers_check",
        "cookie_flags_check",
        "tls_config_check",
        "source_map_detection",
        "non_destructive_endpoint_probe",
    ],
)
def test_client_safe_allows_safe_evidence_collection_actions(action):
    decision = _action_decision(action, profile="client_safe")

    assert _allowed(decision) is True
