"""core/engagement.py
Pentest Engagement — deterministic, offline core contract (Engagement & ROE
Foundation, F1).

An *engagement* is the top-level authorized-pentest envelope that ties a client
and project to the machinery that already exists: a scope, the Rules of
Engagement, an explicit client authorization, and links to the missions, audit
runs and findings that carry the work and its evidence. The lifecycle is

    draft → authorized → active → reporting ⇄ retest → closed → archived

It is a pure, deterministic payload — like :mod:`core.pentest_mission`'s mission:
no stored state, no I/O, no database writes, no network, no subprocess, no GUI,
and it never reads ``FindingsStore`` / ``MissionStore`` / ``AuditRunStore``. It
only builds, normalizes and validates the payload.

Guardrails are reused, never re-implemented: the active/passive ROE consistency
rule comes from :func:`core.audit_scope.validate_roe`, and the canonical export
validates against ``schemas/asa_engagement.schema.json`` via
:mod:`core.audit_schema`. Scope here is a deliberately distinct, simpler shape
(allowed_domains / allowed_ips / forbidden_paths) than the ROE-embedded scope a
mission uses, because an engagement separates *what is in bounds* (scope), *how
to engage* (roe) and *who approved it* (authorization).
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha1
from typing import Any, Dict, Iterable, List, Optional

PROFILE = "client_safe"
REPORT_ORIENTATION = "evidence_first"

# Engagement lifecycle and the legal forward transitions. ``archived`` is
# terminal; every non-terminal state may be archived. Moving to ``authorized``
# and ``closed`` carry extra preconditions (see :func:`advance_engagement_status`).
ENGAGEMENT_TRANSITIONS: Dict[str, frozenset] = {
    "draft": frozenset({"authorized", "archived"}),
    "authorized": frozenset({"active", "draft", "archived"}),
    "active": frozenset({"reporting", "retest", "archived"}),
    "reporting": frozenset({"retest", "closed", "active", "archived"}),
    "retest": frozenset({"reporting", "closed", "active", "archived"}),
    "closed": frozenset({"archived"}),
    "archived": frozenset(),
}
ENGAGEMENT_STATUSES = frozenset(ENGAGEMENT_TRANSITIONS)


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def _stable_id(client: str, project: str) -> str:
    raw = f"{client}|{project}"
    return f"eng-{sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _clean_refs(values: Optional[Iterable[Any]]) -> List[str]:
    """Stripped, de-duplicated, sorted id/list strings (case preserved)."""
    out = {str(v or "").strip() for v in (values or [])}
    return sorted(ref for ref in out if ref)


def _opt_str(value: Any) -> Optional[str]:
    """A trimmed non-empty string, or ``None`` (for nullable scalar fields)."""
    text = str(value).strip() if isinstance(value, str) else ""
    return text or None


def normalize_scope(scope: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical engagement scope: three de-duplicated, sorted string lists."""
    src = scope if isinstance(scope, dict) else {}
    return {
        "allowed_domains": _clean_refs(src.get("allowed_domains")),
        "allowed_ips": _clean_refs(src.get("allowed_ips")),
        "forbidden_paths": _clean_refs(src.get("forbidden_paths")),
    }


def normalize_roe(roe: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical engagement ROE (how to engage; scope lives separately)."""
    src = roe if isinstance(roe, dict) else {}
    return {
        "passive_only": bool(src.get("passive_only", True)),
        "active_scan_enabled": bool(src.get("active_scan_enabled", False)),
        "rate_limit": _opt_str(src.get("rate_limit")),
        "window": _opt_str(src.get("window")),
        "emergency_contact": str(src.get("emergency_contact") or "").strip(),
    }


def normalize_authorization(authorization: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical client authorization block."""
    src = authorization if isinstance(authorization, dict) else {}
    return {
        "accepted": bool(src.get("accepted", False)),
        "authorized_by": str(src.get("authorized_by") or "").strip(),
        "reference": str(src.get("reference") or "").strip(),
        "notes": str(src.get("notes") or "").strip(),
    }


def normalize_engagement(engagement: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical, deterministic engagement dict (pure; idempotent).

    Sorts keys, normalizes scope / roe / authorization, de-duplicates and sorts
    the link lists, lower-cases the status, and pins ``profile`` /
    ``report_orientation`` to their client-safe constants. Never mutates input."""
    src = engagement if isinstance(engagement, dict) else {}
    out = {
        "engagement_id": str(src.get("engagement_id") or "").strip(),
        "client": str(src.get("client") or "").strip(),
        "project": str(src.get("project") or "").strip(),
        "profile": PROFILE,
        "status": str(src.get("status") or "draft").strip().lower(),
        "scope": normalize_scope(src.get("scope")),
        "roe": normalize_roe(src.get("roe")),
        "authorization": normalize_authorization(src.get("authorization")),
        "linked_mission_ids": _clean_refs(src.get("linked_mission_ids")),
        "linked_audit_run_ids": _clean_refs(src.get("linked_audit_run_ids")),
        "linked_finding_ids": _clean_refs(src.get("linked_finding_ids")),
        "report_orientation": REPORT_ORIENTATION,
    }
    return _canonical(out)


def create_engagement(
    client: str,
    project: str,
    *,
    scope: Optional[Dict[str, Any]] = None,
    roe: Optional[Dict[str, Any]] = None,
    authorization: Optional[Dict[str, Any]] = None,
    engagement_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a deterministic ``draft`` engagement payload.

    ``client`` and ``project`` are required. A bare call is deterministic: the
    same client+project yields the same ``engagement_id`` (``eng-`` + a sha1
    prefix). Scope / ROE / authorization are normalized; their validity is
    asserted by :func:`validate_engagement`, not here."""
    clean_client = str(client or "").strip()
    if not clean_client:
        raise ValueError("client is required")
    clean_project = str(project or "").strip()
    if not clean_project:
        raise ValueError("project is required")
    engagement = {
        "engagement_id": str(engagement_id or "").strip()
        or _stable_id(clean_client, clean_project),
        "client": clean_client,
        "project": clean_project,
        "profile": PROFILE,
        "status": "draft",
        "scope": scope,
        "roe": roe,
        "authorization": authorization,
        "linked_mission_ids": [],
        "linked_audit_run_ids": [],
        "linked_finding_ids": [],
        "report_orientation": REPORT_ORIENTATION,
    }
    return normalize_engagement(engagement)


def validate_engagement(engagement: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate an engagement's required fields, guardrails and ROE consistency.

    Returns ``{"valid": bool, "errors": [str], "engagement": <normalized>}`` (the
    same shape as :func:`core.audit_scope.validate_roe`). The active/passive ROE
    rule is checked by reusing ``validate_roe`` over the engagement's scope+roe,
    so the consistency logic is not duplicated here."""
    normalized = normalize_engagement(engagement)
    errors: List[str] = []
    if not normalized["engagement_id"]:
        errors.append("engagement_id is required")
    if not normalized["client"]:
        errors.append("client is required")
    if not normalized["project"]:
        errors.append("project is required")
    if normalized["profile"] != PROFILE:
        errors.append("profile must be client_safe")
    if normalized["report_orientation"] != REPORT_ORIENTATION:
        errors.append("report_orientation must be evidence_first")
    if normalized["status"] not in ENGAGEMENT_STATUSES:
        errors.append(f"unknown engagement status: {normalized['status']}")

    # Reuse the active/passive consistency rule (active requires allowed_domains;
    # active conflicts with passive_only) instead of re-implementing it.
    from core.audit_scope import validate_roe

    roe_check = validate_roe({
        "profile": PROFILE,
        "allowed_domains": normalized["scope"]["allowed_domains"],
        "active_scan_enabled": normalized["roe"]["active_scan_enabled"],
        "passive_only": normalized["roe"]["passive_only"],
    })
    errors.extend(f"roe: {item}" for item in roe_check["errors"])

    return {"valid": not errors, "errors": errors, "engagement": normalized}


def _has_links(engagement: Dict[str, Any]) -> bool:
    return any(engagement.get(key) for key in (
        "linked_mission_ids", "linked_audit_run_ids", "linked_finding_ids"))


def advance_engagement_status(engagement: Dict[str, Any],
                              new_status: str) -> Dict[str, Any]:
    """Return a new engagement moved to ``new_status`` along the legal transitions.

    Illegal transitions (unknown status, or a hop not in
    :data:`ENGAGEMENT_TRANSITIONS`) raise ``ValueError``. Extra preconditions:

    * → ``authorized`` requires a valid engagement (client/project/scope/ROE) **and**
      ``authorization.accepted == true``;
    * → ``closed`` requires at least one linked mission, audit run or finding.

    ``archived`` is terminal. Never mutates the input."""
    current = normalize_engagement(engagement)
    target = str(new_status or "").strip().lower()
    source = current["status"]
    if source not in ENGAGEMENT_TRANSITIONS:
        raise ValueError(f"unknown engagement status: {source}")
    if target not in ENGAGEMENT_STATUSES:
        raise ValueError(f"unknown engagement status: {target}")
    if target not in ENGAGEMENT_TRANSITIONS[source]:
        raise ValueError(f"illegal engagement transition: {source} -> {target}")
    if target == "authorized":
        check = validate_engagement(current)
        if not check["valid"]:
            raise ValueError(
                "engagement is not authorizable: " + "; ".join(check["errors"]))
        if not current["authorization"]["accepted"]:
            raise ValueError(
                "authorization must be accepted before authorizing the engagement")
    if target == "closed" and not _has_links(current):
        raise ValueError(
            "engagement cannot be closed without a linked mission, audit run "
            "or finding")
    updated = deepcopy(current)
    updated["status"] = target
    return normalize_engagement(updated)


def link_mission(engagement: Dict[str, Any], mission_id: str) -> Dict[str, Any]:
    """Return a new engagement with ``mission_id`` added to ``linked_mission_ids``
    (de-duplicated, sorted). References an existing mission; never creates one."""
    clean = str(mission_id or "").strip()
    if not clean:
        raise ValueError("mission_id is required")
    updated = normalize_engagement(engagement)
    updated["linked_mission_ids"] = _clean_refs(
        updated["linked_mission_ids"] + [clean])
    return normalize_engagement(updated)


def link_audit_run(engagement: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    """Return a new engagement with ``run_id`` added to ``linked_audit_run_ids``
    (de-duplicated, sorted). References an existing audit run; never creates one."""
    clean = str(run_id or "").strip()
    if not clean:
        raise ValueError("run_id is required")
    updated = normalize_engagement(engagement)
    updated["linked_audit_run_ids"] = _clean_refs(
        updated["linked_audit_run_ids"] + [clean])
    return normalize_engagement(updated)


def link_finding(engagement: Dict[str, Any], finding_id: str) -> Dict[str, Any]:
    """Return a new engagement with ``finding_id`` added to ``linked_finding_ids``
    (de-duplicated, sorted). Stores the reference only; never reads/writes
    FindingsStore (existence checks are deferred to a later milestone)."""
    clean = str(finding_id or "").strip()
    if not clean:
        raise ValueError("finding_id is required")
    updated = normalize_engagement(engagement)
    updated["linked_finding_ids"] = _clean_refs(
        updated["linked_finding_ids"] + [clean])
    return normalize_engagement(updated)


def engagement_to_json(engagement: Dict[str, Any]) -> Dict[str, Any]:
    """Canonical JSON-serializable engagement export, schema-validated.

    Normalizes, then validates against ``asa_engagement`` (which pins the
    status / profile / report_orientation enums and the nested shapes), so an
    export is always a stable, contract-valid payload."""
    payload = normalize_engagement(engagement)
    from core.audit_schema import validate_audit_payload

    validate_audit_payload(payload, "asa_engagement")
    return payload
