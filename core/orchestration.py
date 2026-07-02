"""Authorized Worker Orchestration (Roadmap E8).

A pure, offline contract for a **central job queue** and **explicit worker-node**
framework — the model that lets authorized scan/audit work be scheduled across
declared nodes for enterprise scaling. This increment is the contract only: it
shapes, validates and schedules jobs/nodes as plain dicts; it holds no state,
runs no threads, opens no sockets, and executes nothing. A persistent store and a
real dispatcher are deferred follow-ups that build on this contract.

Authorization guardrails (baked into the contract, not optional):
- A job may only be claimed by a node that is **explicitly authorized**
  (``authorized=True``), currently **active**, and **declares the capability**
  for that job kind. There is no covert/auto node — a node must be registered and
  authorized before any work reaches it.
- Job kinds are the platform's existing client-safe run types only.

Deterministic throughout (canonical ordering, stable ids) so scheduling is
reproducible and unit-testable without time or network.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha1
from typing import Any, Dict, List, Optional


# The client-safe run kinds a job can wrap — each maps to an existing runner
# (collection_runner / audit_runner / mission_runner / tool_runner /
# retest_runner). No new capability is introduced by orchestration.
JOB_KINDS = (
    "full_collection",
    "audit_run",
    "mission_run",
    "tool_run",
    "retest_run",
)

JOB_STATUSES = ("pending", "claimed", "running", "completed", "failed", "cancelled")

# Legal job status transitions (mirrors the mission/audit lifecycle style).
JOB_TRANSITIONS = {
    "pending": {"claimed", "cancelled"},
    "claimed": {"running", "pending", "cancelled"},   # 'pending' = release back
    "running": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}

NODE_STATUSES = ("active", "draining", "offline")


def _clean(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


# --- worker nodes ------------------------------------------------------------

def _node_id(label: str) -> str:
    return f"node-{sha1(label.encode('utf-8')).hexdigest()[:16]}"


def _capabilities(values: Any) -> List[str]:
    out: List[str] = []
    for item in values or []:
        kind = _clean(item)
        if kind and kind not in JOB_KINDS:
            raise ValueError(f"unknown job kind capability: {kind}")
        if kind and kind not in out:
            out.append(kind)
    return out


def register_node(
    label: str,
    *,
    capabilities: Optional[List[str]] = None,
    authorized: bool = False,
    status: str = "active",
    node_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a normalized worker-node record. ``label`` is required.

    A node is inert until ``authorized=True`` — the explicit-authorization
    guardrail. ``capabilities`` must be a subset of :data:`JOB_KINDS`.
    """
    clean_label = _clean(label)
    if not clean_label:
        raise ValueError("node label is required")
    clean_status = _clean(status) or "active"
    if clean_status not in NODE_STATUSES:
        raise ValueError(f"unknown node status: {clean_status}")
    return {
        "node_id": _clean(node_id) or _node_id(clean_label),
        "label": clean_label,
        "capabilities": _capabilities(capabilities),
        "authorized": bool(authorized),
        "status": clean_status,
        "last_seen": "",
    }


def normalize_node(node: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    src = node if isinstance(node, dict) else {}
    out = register_node(
        src.get("label") or "unnamed",
        capabilities=src.get("capabilities"),
        authorized=bool(src.get("authorized")),
        status=src.get("status") or "active",
        node_id=src.get("node_id"),
    )
    out["last_seen"] = _clean(src.get("last_seen"))
    return out


def node_can_run(node: Optional[Dict[str, Any]], kind: str) -> bool:
    """Whether ``node`` is eligible to run a job of ``kind``: authorized, active,
    and declaring that capability. This is the single assignment gate."""
    n = normalize_node(node)
    return bool(
        n["authorized"]
        and n["status"] == "active"
        and _clean(kind) in n["capabilities"]
    )


def node_to_json(node: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return _canonical(normalize_node(node))


# --- jobs --------------------------------------------------------------------

def _job_id(kind: str, target: str, created_at: str) -> str:
    raw = f"{kind}|{target}|{created_at}"
    return f"job-{sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def create_job(
    kind: str,
    *,
    project: str = "",
    target: str = "",
    params: Optional[Dict[str, Any]] = None,
    priority: int = 0,
    created_at: str = "",
    job_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a normalized, pending job. ``kind`` must be a known job kind."""
    clean_kind = _clean(kind)
    if clean_kind not in JOB_KINDS:
        raise ValueError(f"unknown job kind: {clean_kind}")
    clean_created = _clean(created_at)
    return {
        "job_id": _clean(job_id) or _job_id(clean_kind, _clean(target), clean_created),
        "kind": clean_kind,
        "project": _clean(project),
        "target": _clean(target),
        "params": _canonical(params if isinstance(params, dict) else {}),
        "priority": int(priority) if isinstance(priority, (int, float)) else 0,
        "status": "pending",
        "node_id": "",
        "created_at": clean_created,
        "updated_at": clean_created,
        "result_ref": "",
    }


def normalize_job(job: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    src = job if isinstance(job, dict) else {}
    base = create_job(
        src.get("kind") or "full_collection",
        project=src.get("project", ""),
        target=src.get("target", ""),
        params=src.get("params"),
        priority=src.get("priority", 0),
        created_at=src.get("created_at", ""),
        job_id=src.get("job_id"),
    )
    status = _clean(src.get("status")) or "pending"
    if status not in JOB_STATUSES:
        raise ValueError(f"unknown job status: {status}")
    base["status"] = status
    base["node_id"] = _clean(src.get("node_id"))
    base["updated_at"] = _clean(src.get("updated_at")) or base["created_at"]
    base["result_ref"] = _clean(src.get("result_ref"))
    return base


def validate_job(job: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return ``{valid, errors, job}``. A claimed/running job must name a node."""
    normalized = normalize_job(job)
    errors: List[str] = []
    if normalized["kind"] not in JOB_KINDS:
        errors.append("unknown job kind")
    if normalized["status"] in ("claimed", "running") and not normalized["node_id"]:
        errors.append(f"a {normalized['status']} job must be assigned to a node")
    return {"valid": not errors, "errors": errors, "job": normalized}


def advance_job_status(
    job: Optional[Dict[str, Any]],
    status: str,
    *,
    now: str = "",
) -> Dict[str, Any]:
    """Return a copy of ``job`` moved to ``status`` if the transition is legal."""
    current = normalize_job(job)
    target = _clean(status)
    if target not in JOB_STATUSES:
        raise ValueError(f"unknown job status: {target}")
    if target not in JOB_TRANSITIONS.get(current["status"], set()):
        raise ValueError(
            f"illegal job transition: {current['status']} -> {target}")
    updated = deepcopy(current)
    updated["status"] = target
    if now:
        updated["updated_at"] = _clean(now)
    if target == "pending":         # released back to the queue
        updated["node_id"] = ""
    return updated


def assign_job(
    job: Optional[Dict[str, Any]],
    node: Optional[Dict[str, Any]],
    *,
    now: str = "",
) -> Dict[str, Any]:
    """Claim a pending ``job`` for ``node`` (authorization-gated).

    Raises if the job is not pending or the node is not eligible
    (:func:`node_can_run`). Returns the claimed job stamped with the node id.
    """
    current = normalize_job(job)
    n = normalize_node(node)
    if current["status"] != "pending":
        raise ValueError("only a pending job can be assigned")
    if not node_can_run(n, current["kind"]):
        raise ValueError(
            f"node {n['node_id']} is not authorized/capable for kind "
            f"{current['kind']}")
    claimed = advance_job_status(current, "claimed", now=now)
    claimed["node_id"] = n["node_id"]
    return claimed


def claim_next(
    jobs: Any,
    node: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """The best pending job ``node`` may claim, or ``None``.

    Eligible jobs are pending and of a kind the node can run; ranked by highest
    priority, then oldest ``created_at``, then ``job_id`` (a stable tie-break).
    Pure — it selects; it does not mutate the queue. Use :func:`assign_job` on
    the result to produce the claimed job.
    """
    n = normalize_node(node)
    eligible: List[Dict[str, Any]] = []
    for raw in jobs or []:
        job = normalize_job(raw)
        if job["status"] == "pending" and node_can_run(n, job["kind"]):
            eligible.append(job)
    if not eligible:
        return None
    eligible.sort(key=lambda j: (-j["priority"], j["created_at"], j["job_id"]))
    return eligible[0]


def job_to_json(job: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return _canonical(normalize_job(job))
