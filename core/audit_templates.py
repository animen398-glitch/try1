"""Audit scenario templates for the Client-Safe Pentest Workbench (v2).

Pure, stateless registry. A template is *configuration only*: it selects the
ordered audit phases to run, a subset of safe active checks, a recommended ROE
template name, a quality-gate confidence floor, and client-safe scenario flags.
It holds no state and performs no I/O.

The actual binding of ``roe_template`` name -> normalized ROE dict belongs to
F2 (``core.audit_scope``); here a template only records the recommended name.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional

from core.audit_checks import SAFE_CHECKS
from core.audit_workflow import AUDIT_PHASES


# Canonical scenario templates. ``phases`` is an ordered subset of AUDIT_PHASES;
# ``safe_checks`` is a subset of ``audit_checks.SAFE_CHECKS``. All flags stay
# client-safe: ``auth_context`` means an operator-supplied authorized session,
# never credential acquisition.
AUDIT_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "light_client_safe": {
        "label": "Light Client-Safe",
        "description": "Fast passive-leaning pass: recon, hunt, validation, report.",
        "phases": [
            "recon_snapshot",
            "finding_hunt",
            "validation",
            "structured_output",
        ],
        "safe_checks": [
            "headers_check",
            "cookie_flags_check",
            "source_map_detection",
        ],
        "roe_template": "passive_external",
        "min_confidence": 70,
        "auth_context": False,
        "revalidate_unresolved": False,
        "compare_to_baseline": False,
    },
    "authenticated_review": {
        "label": "Authenticated Review",
        "description": (
            "Full review using an operator-supplied authorized session. Only "
            "safe active checks; the tool never acquires or guesses credentials."
        ),
        "phases": list(AUDIT_PHASES),
        "safe_checks": list(SAFE_CHECKS),
        "roe_template": "authenticated_internal",
        "min_confidence": 75,
        "auth_context": True,
        "revalidate_unresolved": False,
        "compare_to_baseline": False,
    },
    "evidence_refresh": {
        "label": "Evidence Refresh",
        "description": (
            "Re-check existing unresolved findings and their evidence; "
            "no new finding hunt."
        ),
        "phases": [
            "recon_snapshot",
            "validation",
            "independent_verification",
        ],
        "safe_checks": [],
        "roe_template": "evidence_only",
        "min_confidence": 70,
        "auth_context": False,
        "revalidate_unresolved": True,
        "compare_to_baseline": False,
    },
    "release_regression": {
        "label": "Release Regression Audit",
        "description": "Full pass compared against a baseline run to gate a release.",
        "phases": list(AUDIT_PHASES),
        "safe_checks": list(SAFE_CHECKS),
        "roe_template": "release_gate",
        "min_confidence": 75,
        "auth_context": False,
        "revalidate_unresolved": False,
        "compare_to_baseline": True,
    },
}


def _check_template(name: str, tpl: Dict[str, Any]) -> None:
    """Guard a template's internal consistency (offline, deterministic)."""
    for phase in tpl.get("phases") or []:
        if phase not in AUDIT_PHASES:
            raise ValueError(f"template {name}: unknown audit phase: {phase}")
    if not tpl.get("phases"):
        raise ValueError(f"template {name}: at least one phase is required")
    for check in tpl.get("safe_checks") or []:
        if check not in SAFE_CHECKS:
            raise ValueError(f"template {name}: unknown safe check: {check}")


def list_templates() -> List[Dict[str, Any]]:
    """Return all templates as a stable, name-sorted list of deep copies."""
    out: List[Dict[str, Any]] = []
    for name in sorted(AUDIT_TEMPLATES):
        tpl = deepcopy(AUDIT_TEMPLATES[name])
        tpl["name"] = name
        out.append(tpl)
    return out


def get_template(name: str) -> Dict[str, Any]:
    """Return one template (deep copy, with ``name``); raise on unknown."""
    key = str(name or "").strip()
    if key not in AUDIT_TEMPLATES:
        raise ValueError(f"unknown audit template: {key}")
    tpl = deepcopy(AUDIT_TEMPLATES[key])
    tpl["name"] = key
    return tpl


def resolve_template(
    name: str,
    *,
    phases: Optional[List[str]] = None,
    roe: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolve a template into concrete run configuration.

    ``phases`` overrides the template phase list; ``roe`` is an explicit ROE
    override carried through unchanged (normalization happens in the workflow).
    """
    tpl = get_template(name)
    _check_template(tpl["name"], tpl)
    resolved_phases = list(phases) if phases else list(tpl["phases"])
    for phase in resolved_phases:
        if phase not in AUDIT_PHASES:
            raise ValueError(f"unknown audit phase: {phase}")
    return {
        "name": tpl["name"],
        "phases": resolved_phases,
        "safe_checks": list(tpl["safe_checks"]),
        "roe_template": tpl["roe_template"],
        "min_confidence": int(tpl["min_confidence"]),
        "auth_context": bool(tpl["auth_context"]),
        "revalidate_unresolved": bool(tpl["revalidate_unresolved"]),
        "compare_to_baseline": bool(tpl["compare_to_baseline"]),
        "roe": roe,
    }
