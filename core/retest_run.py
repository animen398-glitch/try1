"""core/retest_run.py
Retest Run — deterministic, offline core contract (Retest Run lifecycle, R1).

A *retest run* is a persisted, point-in-time **snapshot** of an engagement's
linked-finding outcomes: what had been remediated (``fixed``), what was still
``open``, what had been risk-``accepted`` and what had gone ``missing`` at the
moment the retest was taken. Where :mod:`core.engagement_retest` is a live
derive-on-read *view* (always recomputed against the current FindingsStore), a
retest run freezes one such view so an engagement accrues a history of retests
and shows remediation progress over time.

This module is the pure contract only — mirroring :mod:`core.pentest_mission` and
:mod:`core.engagement`: it builds, normalizes, validates and advances a retest-run
payload, but it has no stored state, no I/O, no database writes, no network and
never reads ``FindingsStore``. Computing the per-finding outcomes (the non-trivial
status → outcome mapping) stays in :func:`core.engagement_retest.build_retest`;
:mod:`core.retest_runner` wires that snapshot into this contract and persists it.

The lifecycle is intentionally short — a retest needs no network, so it completes
as soon as the snapshot is taken:

    pending → completed
    pending → failed

``completed`` and ``failed`` are terminal (a fresh retest is a new record). The
canonical export validates against ``schemas/asa_retest_run.schema.json`` via
:mod:`core.audit_schema`.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha1
from typing import Any, Dict, Iterable, List, Optional

PROFILE = "client_safe"

# The outcomes a retested finding can land on (mirrors engagement_retest).
RETEST_OUTCOMES = frozenset({"fixed", "open", "accepted", "missing"})

# Retest-run lifecycle and the legal forward transitions. A retest is synchronous
# (no network), so ``pending`` only ever moves to a terminal ``completed`` /
# ``failed``; both terminals are dead-ends.
RETEST_RUN_TRANSITIONS: Dict[str, frozenset] = {
    "pending": frozenset({"completed", "failed"}),
    "completed": frozenset(),
    "failed": frozenset(),
}
RETEST_RUN_STATUSES = frozenset(RETEST_RUN_TRANSITIONS)


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def _stable_id(engagement_id: str, created_at: str) -> str:
    raw = f"{engagement_id}|{created_at}"
    return f"rt-{sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _outcome(value: Any) -> str:
    """A recognized outcome string, defaulting unknowns to ``open``."""
    text = str(value or "").strip().lower()
    return text if text in RETEST_OUTCOMES else "open"


def normalize_finding_result(item: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical one-finding snapshot row (the shape produced by ``build_retest``).

    ``missing`` findings (deleted since the link was made) are preserved, never
    faked. ``outcome`` is clamped to :data:`RETEST_OUTCOMES`."""
    src = item if isinstance(item, dict) else {}
    missing = bool(src.get("missing", False))
    outcome = "missing" if missing else _outcome(src.get("outcome"))
    return {
        "finding_id": str(src.get("finding_id") or "").strip(),
        "missing": missing,
        "outcome": outcome,
        "title": str(src.get("title") or ""),
        "severity": str(src.get("severity") or ""),
        "status": str(src.get("status") or ""),
    }


def _normalize_results(results: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    rows = [normalize_finding_result(item) for item in (results or [])]
    # Deterministic order: by finding_id, then outcome (stable across re-normalize).
    return sorted(rows, key=lambda r: (r["finding_id"], r["outcome"]))


def summarize(results: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """Outcome counts for a list of finding-result rows (the contract invariant).

    The summary is always recomputed from the results so it can never drift; the
    per-finding outcomes themselves come from ``engagement_retest.build_retest``."""
    rows = list(results or [])
    return {
        "total": len(rows),
        "fixed": sum(1 for r in rows if r.get("outcome") == "fixed"),
        "open": sum(1 for r in rows if r.get("outcome") == "open"),
        "accepted": sum(1 for r in rows if r.get("outcome") == "accepted"),
        "missing": sum(1 for r in rows if r.get("outcome") == "missing"),
    }


def normalize_retest_run(run: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Canonical, deterministic retest-run dict (pure; idempotent).

    Normalizes the finding-result rows, recomputes ``summary`` from them, lower-
    cases the status and pins ``profile`` to its client-safe constant. Never
    mutates input."""
    src = run if isinstance(run, dict) else {}
    results = _normalize_results(src.get("finding_results"))
    out = {
        "retest_run_id": str(src.get("retest_run_id") or "").strip(),
        "engagement_id": str(src.get("engagement_id") or "").strip(),
        "client": str(src.get("client") or "").strip(),
        "project": str(src.get("project") or "").strip(),
        "profile": PROFILE,
        "status": str(src.get("status") or "pending").strip().lower(),
        "created_at": str(src.get("created_at") or "").strip(),
        "finding_results": results,
        "summary": summarize(results),
    }
    return _canonical(out)


def create_retest_run(
    engagement: Dict[str, Any],
    *,
    created_at: str,
    finding_results: Optional[Iterable[Any]] = None,
    status: str = "pending",
    retest_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a deterministic retest-run payload for ``engagement``.

    ``engagement`` supplies the ``engagement_id`` / ``client`` / ``project``;
    ``created_at`` is required (it discriminates otherwise-identical runs and
    seeds the id). ``finding_results`` is the per-finding snapshot (typically
    ``engagement_retest.build_retest(...)["findings"]``); the ``summary`` is
    derived, never passed in. Raises ``ValueError`` on a missing engagement id or
    ``created_at``."""
    from core.engagement import normalize_engagement

    normalized_eng = normalize_engagement(engagement)
    engagement_id = normalized_eng["engagement_id"]
    if not engagement_id:
        raise ValueError("engagement_id is required")
    stamp = str(created_at or "").strip()
    if not stamp:
        raise ValueError("created_at is required")
    run = {
        "retest_run_id": str(retest_run_id or "").strip()
        or _stable_id(engagement_id, stamp),
        "engagement_id": engagement_id,
        "client": normalized_eng["client"],
        "project": normalized_eng["project"],
        "profile": PROFILE,
        "status": str(status or "pending").strip().lower(),
        "created_at": stamp,
        "finding_results": finding_results,
    }
    return normalize_retest_run(run)


def validate_retest_run(run: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate a retest run's required fields and enums.

    Returns ``{"valid": bool, "errors": [str], "retest_run": <normalized>}`` (the
    same shape as :func:`core.engagement.validate_engagement`)."""
    normalized = normalize_retest_run(run)
    errors: List[str] = []
    if not normalized["retest_run_id"]:
        errors.append("retest_run_id is required")
    if not normalized["engagement_id"]:
        errors.append("engagement_id is required")
    if not normalized["project"]:
        errors.append("project is required")
    if not normalized["created_at"]:
        errors.append("created_at is required")
    if normalized["profile"] != PROFILE:
        errors.append("profile must be client_safe")
    if normalized["status"] not in RETEST_RUN_STATUSES:
        errors.append(f"unknown retest run status: {normalized['status']}")
    for idx, row in enumerate(normalized["finding_results"]):
        if row["outcome"] not in RETEST_OUTCOMES:
            errors.append(f"finding_results[{idx}] has invalid outcome")
        if not row["finding_id"] and not row["missing"]:
            errors.append(f"finding_results[{idx}] is missing finding_id")
    return {"valid": not errors, "errors": errors, "retest_run": normalized}


def advance_retest_run_status(run: Dict[str, Any],
                              new_status: str) -> Dict[str, Any]:
    """Return a new retest run moved to ``new_status`` along the legal transitions.

    Illegal transitions (unknown status, or a hop not in
    :data:`RETEST_RUN_TRANSITIONS`) raise ``ValueError``. ``completed`` and
    ``failed`` are terminal. Never mutates the input."""
    current = normalize_retest_run(run)
    target = str(new_status or "").strip().lower()
    source = current["status"]
    if source not in RETEST_RUN_TRANSITIONS:
        raise ValueError(f"unknown retest run status: {source}")
    if target not in RETEST_RUN_STATUSES:
        raise ValueError(f"unknown retest run status: {target}")
    if target not in RETEST_RUN_TRANSITIONS[source]:
        raise ValueError(f"illegal retest run transition: {source} -> {target}")
    updated = deepcopy(current)
    updated["status"] = target
    return normalize_retest_run(updated)


def retest_run_to_json(run: Dict[str, Any]) -> Dict[str, Any]:
    """Canonical JSON-serializable retest-run export, schema-validated.

    Normalizes, then validates against ``asa_retest_run`` (which pins the status /
    profile / outcome enums and the nested shapes), so an export is always a
    stable, contract-valid payload."""
    payload = normalize_retest_run(run)
    from core.audit_schema import validate_audit_payload

    validate_audit_payload(payload, "asa_retest_run")
    return payload
