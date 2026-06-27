"""Persistent Audit Run store for Client-Safe Pentest Workbench.

This is storage for audit-run payloads, not a second findings source of truth.
The canonical export remains the JSON returned by ``audit_run_to_json`` and
validated by ``asa_audit_run.schema.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.audit_schema import validate_audit_payload
from core.audit_workflow import audit_run_to_json
from core.config import get_path_manager
from utils.sqlite_store import SQLiteStore, now_ts as _now


def _default_db_path() -> Path:
    return get_path_manager().get_db_path("audit_runs.db")


class AuditRunStore(SQLiteStore):
    """SQLite-backed persistence for audit runs + audit-level events."""

    JSON_FIELDS = ("payload",)
    SCHEMA_VERSION = 1

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS audit_runs (
        id         TEXT PRIMARY KEY,
        project    TEXT NOT NULL,
        profile    TEXT NOT NULL,
        status     TEXT NOT NULL,
        payload    TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id     TEXT NOT NULL,
        type       TEXT NOT NULL,
        phase      TEXT,
        finding_id TEXT,
        note       TEXT,
        at         TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_audit_runs_project ON audit_runs(project, updated_at);
    CREATE INDEX IF NOT EXISTS ix_audit_events_run ON audit_events(run_id, id);
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or _default_db_path())

    @staticmethod
    def _payload_json(run: Dict[str, Any]) -> Dict[str, Any]:
        payload = audit_run_to_json(run)
        validate_audit_payload(payload, "asa_audit_run")
        return payload

    def save_run(self, run: Dict[str, Any], *, now: Optional[str] = None) -> Dict[str, Any]:
        """Insert or replace one audit run by ``run_id``.

        Duplicate saves are idempotent: the existing ``created_at`` is preserved,
        while status/payload/updated_at move to the latest canonical payload.
        """
        payload = self._payload_json(run)
        run_id = str(payload.get("run_id") or "").strip()
        project = str(payload.get("project") or "").strip()
        profile = str(payload.get("profile") or "client_safe").strip()
        status = str(payload.get("status") or "").strip()
        if not run_id:
            raise ValueError("run_id is required")
        if not project:
            raise ValueError("project is required")
        stamp = now or _now()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM audit_runs WHERE id = ?", (run_id,)
            ).fetchone()
            created_at = existing["created_at"] if existing is not None else stamp
            conn.execute(
                "INSERT INTO audit_runs"
                " (id, project, profile, status, payload, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " project = excluded.project,"
                " profile = excluded.profile,"
                " status = excluded.status,"
                " payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (run_id, project, profile, status, encoded, created_at, stamp),
            )
            row = conn.execute("SELECT * FROM audit_runs WHERE id = ?", (run_id,)).fetchone()
        return self._row_to_dict(row)

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM audit_runs WHERE id = ?", (str(run_id),)
            ).fetchone()
        return self._row_to_dict(row)

    def list_runs(self, project: Optional[str] = None) -> List[Dict[str, Any]]:
        params: list = []
        where = ""
        if project is not None:
            where = " WHERE project = ?"
            params.append(project)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_runs{where} ORDER BY updated_at DESC, id DESC",
                params,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_run(self, run_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM audit_runs WHERE id = ?", (str(run_id),))
            conn.execute("DELETE FROM audit_events WHERE run_id = ?", (str(run_id),))
        return bool(cur.rowcount)

    def record_event(
        self,
        run_id: str,
        event_type: str,
        *,
        phase: Optional[str] = None,
        finding_id: Optional[str] = None,
        note: Optional[Union[str, Dict[str, Any]]] = None,
        at: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.get_run(run_id) is None:
            raise KeyError(run_id)
        if isinstance(note, dict):
            note_value = json.dumps(note, ensure_ascii=False, sort_keys=True)
        else:
            note_value = note
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO audit_events"
                " (run_id, type, phase, finding_id, note, at)"
                " VALUES (?,?,?,?,?,?)",
                (str(run_id), str(event_type), phase, finding_id, note_value, at or _now()),
            )
            row = conn.execute(
                "SELECT * FROM audit_events WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
        return dict(row)

    def events(self, run_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE run_id = ? ORDER BY id", (str(run_id),)
            ).fetchall()
        return [dict(row) for row in rows]

    def export_run(self, run_id: str) -> Dict[str, Any]:
        row = self.get_run(run_id)
        if row is None:
            raise KeyError(run_id)
        payload = audit_run_to_json(row["payload"])
        validate_audit_payload(payload, "asa_audit_run")
        return payload
