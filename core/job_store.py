"""Persistence for Authorized Worker Orchestration (Roadmap E8, increment 2).

SQLite-backed stores for the pure orchestration contract in
:mod:`core.orchestration`: a :class:`JobStore` (the central queue) and a
:class:`NodeStore` (the registry of explicit worker nodes). Each mirrors
:class:`core.mission_store.MissionStore` — single-table, events-less, and it
schema-validates the canonical payload before every write, so the store never
holds a job/node that the contract would reject.

No execution here — running a claimed job is the dispatcher's job
(:mod:`core.job_dispatcher`). Offline, stdlib-only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.audit_schema import validate_audit_payload
from core.config import get_path_manager
from core.orchestration import (
    assign_job,
    claim_next,
    job_to_json,
    node_to_json,
)
from utils.sqlite_store import SQLiteStore, now_ts as _now


def _jobs_db() -> Path:
    return get_path_manager().get_db_path("jobs.db")


def _nodes_db() -> Path:
    return get_path_manager().get_db_path("nodes.db")


class JobStore(SQLiteStore):
    """SQLite-backed job queue (single table, no event log)."""

    JSON_FIELDS = ("payload",)
    PROJECT_EXPORT = ("jobs", None, None)

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS jobs (
        id         TEXT PRIMARY KEY,
        kind       TEXT NOT NULL,
        project    TEXT NOT NULL,
        status     TEXT NOT NULL,
        node_id    TEXT NOT NULL,
        priority   INTEGER NOT NULL,
        payload    TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status, priority, created_at);
    CREATE INDEX IF NOT EXISTS ix_jobs_project ON jobs(project, updated_at);
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or _jobs_db())

    def save_job(self, job: Dict[str, Any], *,
                 now: Optional[str] = None) -> Dict[str, Any]:
        """Insert or replace one job by ``job_id`` (idempotent, schema-checked)."""
        payload = job_to_json(job)
        validate_audit_payload(payload, "asa_job")
        job_id = str(payload.get("job_id") or "").strip()
        if not job_id:
            raise ValueError("job_id is required")
        stamp = now or _now()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM jobs WHERE id = ?", (job_id,)).fetchone()
            created_at = existing["created_at"] if existing is not None else (
                payload.get("created_at") or stamp)
            conn.execute(
                "INSERT INTO jobs"
                " (id, kind, project, status, node_id, priority, payload,"
                "  created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " kind = excluded.kind, project = excluded.project,"
                " status = excluded.status, node_id = excluded.node_id,"
                " priority = excluded.priority, payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (job_id, payload["kind"], payload["project"], payload["status"],
                 payload["node_id"], int(payload["priority"]), encoded,
                 created_at, stamp))
            row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._row_to_dict(row)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (str(job_id),)).fetchone()
        return self._row_to_dict(row)

    def list_jobs(self, *, project: Optional[str] = None,
                  status: Optional[str] = None) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if project is not None:
            clauses.append("project = ?")
            params.append(project)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM jobs{where}"
                " ORDER BY priority DESC, created_at ASC, id ASC", params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_job(self, job_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM jobs WHERE id = ?", (str(job_id),))
        return bool(cur.rowcount)

    def claim_next_job(self, node: Dict[str, Any], *,
                       now: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Claim the best pending job for ``node`` and persist the claim.

        Uses the pure scheduler (:func:`core.orchestration.claim_next`) over the
        current pending jobs, then :func:`assign_job` (authorization-gated) and
        saves the claimed job. Returns the claimed job, or ``None`` if the node
        is not eligible for any pending job.
        """
        # The scheduler works on the canonical (pure) job dicts, not store rows
        # (which nest the job under ``payload``) — extract them first.
        pending = [row["payload"] for row in self.list_jobs(status="pending")
                   if isinstance(row.get("payload"), dict)]
        pick = claim_next(pending, node)
        if pick is None:
            return None
        claimed = assign_job(pick, node, now=now)
        return self.save_job(claimed, now=now)


class NodeStore(SQLiteStore):
    """SQLite-backed registry of explicit worker nodes (single table)."""

    JSON_FIELDS = ("payload",)

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS nodes (
        id         TEXT PRIMARY KEY,
        label      TEXT NOT NULL,
        authorized INTEGER NOT NULL,
        status     TEXT NOT NULL,
        payload    TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or _nodes_db())

    def save_node(self, node: Dict[str, Any], *,
                  now: Optional[str] = None) -> Dict[str, Any]:
        payload = node_to_json(node)
        validate_audit_payload(payload, "asa_worker_node")
        node_id = str(payload.get("node_id") or "").strip()
        if not node_id:
            raise ValueError("node_id is required")
        stamp = now or _now()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM nodes WHERE id = ?", (node_id,)).fetchone()
            created_at = existing["created_at"] if existing is not None else stamp
            conn.execute(
                "INSERT INTO nodes"
                " (id, label, authorized, status, payload, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " label = excluded.label, authorized = excluded.authorized,"
                " status = excluded.status, payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (node_id, payload["label"], 1 if payload["authorized"] else 0,
                 payload["status"], encoded, created_at, stamp))
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return self._row_to_dict(row)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM nodes WHERE id = ?", (str(node_id),)).fetchone()
        return self._row_to_dict(row)

    def list_nodes(self, *, authorized: Optional[bool] = None) -> List[Dict[str, Any]]:
        where, params = "", []
        if authorized is not None:
            where = " WHERE authorized = ?"
            params.append(1 if authorized else 0)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM nodes{where} ORDER BY label ASC, id ASC",
                params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_node(self, node_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM nodes WHERE id = ?", (str(node_id),))
        return bool(cur.rowcount)
