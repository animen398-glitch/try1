"""core/retest_run_store.py
Persistent store for Retest Runs (Retest Run lifecycle, R2).

Storage for retest-run snapshots, not a second findings source: the canonical
export remains the JSON produced by :func:`core.retest_run.retest_run_to_json`
and validated by ``asa_retest_run.schema.json``; the per-finding outcomes were
computed once by :func:`core.engagement_retest.build_retest` and frozen into the
snapshot. Mirrors :class:`core.mission_store.MissionStore` /
:class:`core.engagement_store.EngagementStore` — single-table (a retest run
carries no event log), so it declares an events-less ``PROJECT_EXPORT`` and the
faithful project slice is just the retest-run rows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.config import get_path_manager
from core.retest_run import retest_run_to_json
from utils.sqlite_store import SQLiteStore, now_ts as _now


def _default_db_path() -> Path:
    return get_path_manager().get_db_path("retest_runs.db")


RETEST_RUNS_DB = _default_db_path()


class RetestRunStore(SQLiteStore):
    """SQLite-backed persistence for retest runs (single table, no event log)."""

    JSON_FIELDS = ("payload",)
    # Single-table project slice: retest-run rows only (events_table=None).
    PROJECT_EXPORT = ("retest_runs", None, None)
    SCHEMA_VERSION = 1

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS retest_runs (
        id            TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL,
        project       TEXT NOT NULL,
        status        TEXT NOT NULL,
        payload       TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_retest_runs_engagement
        ON retest_runs(engagement_id, created_at);
    CREATE INDEX IF NOT EXISTS ix_retest_runs_project
        ON retest_runs(project, created_at);
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or RETEST_RUNS_DB)

    @staticmethod
    def _payload_json(run: Dict[str, Any]) -> Dict[str, Any]:
        # Normalizes + schema-validates (asa_retest_run) before any write.
        return retest_run_to_json(run)

    def save_retest_run(self, run: Dict[str, Any], *,
                        now: Optional[str] = None) -> Dict[str, Any]:
        """Insert or replace one retest run by ``retest_run_id``.

        The store ``created_at`` mirrors the snapshot time carried in the payload
        (falling back to ``now`` if absent); duplicate saves are idempotent — the
        existing ``created_at`` is preserved while status/payload/updated_at move
        to the latest canonical payload."""
        payload = self._payload_json(run)
        run_id = str(payload.get("retest_run_id") or "").strip()
        engagement_id = str(payload.get("engagement_id") or "").strip()
        project = str(payload.get("project") or "").strip()
        status = str(payload.get("status") or "").strip()
        if not run_id:
            raise ValueError("retest_run_id is required")
        if not engagement_id:
            raise ValueError("engagement_id is required")
        if not project:
            raise ValueError("project is required")
        stamp = now or _now()
        snapshot_at = str(payload.get("created_at") or "").strip() or stamp
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM retest_runs WHERE id = ?", (run_id,)
            ).fetchone()
            created_at = existing["created_at"] if existing is not None else snapshot_at
            conn.execute(
                "INSERT INTO retest_runs"
                " (id, engagement_id, project, status, payload,"
                "  created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " engagement_id = excluded.engagement_id,"
                " project = excluded.project,"
                " status = excluded.status,"
                " payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (run_id, engagement_id, project, status, encoded,
                 created_at, stamp),
            )
            row = conn.execute(
                "SELECT * FROM retest_runs WHERE id = ?", (run_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def get_retest_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM retest_runs WHERE id = ?", (str(run_id),)
            ).fetchone()
        return self._row_to_dict(row)

    def list_retest_runs(self, *, engagement_id: Optional[str] = None,
                         project: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retest runs, newest snapshot first, optionally filtered by engagement
        and/or project (AND-combined when both are given)."""
        clauses: list = []
        params: list = []
        if engagement_id is not None:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if project is not None:
            clauses.append("project = ?")
            params.append(project)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM retest_runs{where}"
                " ORDER BY created_at DESC, id DESC",
                params,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_retest_run(self, run_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM retest_runs WHERE id = ?", (str(run_id),)
            )
        return bool(cur.rowcount)

    def export_retest_run(self, run_id: str) -> Dict[str, Any]:
        row = self.get_retest_run(run_id)
        if row is None:
            raise KeyError(run_id)
        return retest_run_to_json(row["payload"])
