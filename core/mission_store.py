"""core/mission_store.py
Persistent store for Mission Center missions (Authorized Pentest Multitool, M2).

Storage for mission payloads, not a second findings/asset/timeline source: the
canonical export remains the JSON produced by
:func:`core.pentest_mission.mission_to_json` and validated by
``asa_pentest_mission.schema.json``. Mirrors :class:`core.audit_store.AuditRunStore`
but is single-table — a mission carries no event log in the M1 contract — so it
declares an events-less ``PROJECT_EXPORT`` and the faithful project slice is just
the mission rows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.config import get_path_manager
from core.pentest_mission import mission_to_json
from utils.sqlite_store import SQLiteStore, now_ts as _now


def _default_db_path() -> Path:
    return get_path_manager().get_db_path("missions.db")


MISSIONS_DB = _default_db_path()


class MissionStore(SQLiteStore):
    """SQLite-backed persistence for missions (single table, no event log)."""

    JSON_FIELDS = ("payload", "schedule")
    # Single-table project slice: mission rows only (events_table=None).
    PROJECT_EXPORT = ("missions", None, None)
    SCHEMA_VERSION = 2

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS missions (
        id         TEXT PRIMARY KEY,
        project    TEXT NOT NULL,
        profile    TEXT NOT NULL,
        status     TEXT NOT NULL,
        payload    TEXT NOT NULL,
        schedule   TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_missions_project ON missions(project, updated_at);
    """

    # v2 adds the recurring-schedule column to existing DBs (M9). The schedule is
    # operational state kept *separate* from the canonical ``payload`` so the M1
    # mission contract/schema stays pure. ``_add_column`` is idempotent.
    MIGRATIONS = {
        2: lambda conn: SQLiteStore._add_column(conn, "missions", "schedule TEXT"),
    }

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or MISSIONS_DB)

    @staticmethod
    def _payload_json(mission: Dict[str, Any]) -> Dict[str, Any]:
        # Normalizes + schema-validates (asa_pentest_mission) before any write.
        return mission_to_json(mission)

    def save_mission(self, mission: Dict[str, Any], *,
                     now: Optional[str] = None) -> Dict[str, Any]:
        """Insert or replace one mission by ``mission_id``.

        Duplicate saves are idempotent: the existing ``created_at`` is preserved
        while status/payload/updated_at move to the latest canonical payload."""
        payload = self._payload_json(mission)
        mission_id = str(payload.get("mission_id") or "").strip()
        project = str(payload.get("project") or "").strip()
        profile = str(payload.get("profile") or "client_safe").strip()
        status = str(payload.get("status") or "").strip()
        if not mission_id:
            raise ValueError("mission_id is required")
        if not project:
            raise ValueError("project is required")
        stamp = now or _now()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM missions WHERE id = ?", (mission_id,)
            ).fetchone()
            created_at = existing["created_at"] if existing is not None else stamp
            conn.execute(
                "INSERT INTO missions"
                " (id, project, profile, status, payload, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " project = excluded.project,"
                " profile = excluded.profile,"
                " status = excluded.status,"
                " payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (mission_id, project, profile, status, encoded, created_at, stamp),
            )
            row = conn.execute(
                "SELECT * FROM missions WHERE id = ?", (mission_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM missions WHERE id = ?", (str(mission_id),)
            ).fetchone()
        return self._row_to_dict(row)

    def list_missions(self, project: Optional[str] = None) -> List[Dict[str, Any]]:
        params: list = []
        where = ""
        if project is not None:
            where = " WHERE project = ?"
            params.append(project)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM missions{where} ORDER BY updated_at DESC, id DESC",
                params,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_mission(self, mission_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM missions WHERE id = ?", (str(mission_id),)
            )
        return bool(cur.rowcount)

    def export_mission(self, mission_id: str) -> Dict[str, Any]:
        row = self.get_mission(mission_id)
        if row is None:
            raise KeyError(mission_id)
        return mission_to_json(row["payload"])

    # ── recurring schedule (M9) — operational state, separate from payload ──────

    def set_schedule(self, mission_id: str,
                     schedule: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Attach (or clear, when ``schedule`` is None) a recurring schedule to a
        mission. The mission's ``updated_at``/``payload`` are untouched — the
        schedule is operational metadata, not part of the canonical contract."""
        encoded = (json.dumps(schedule, ensure_ascii=False, sort_keys=True)
                   if schedule is not None else None)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE missions SET schedule = ? WHERE id = ?",
                (encoded, str(mission_id)))
            if cur.rowcount == 0:
                raise KeyError(mission_id)
        return self.get_mission(mission_id)

    def get_schedule(self, mission_id: str) -> Optional[Dict[str, Any]]:
        row = self.get_mission(mission_id)
        schedule = row.get("schedule") if row else None
        return schedule if isinstance(schedule, dict) else None

    def list_scheduled(self) -> List[Dict[str, Any]]:
        """Missions that carry a schedule dict (enabled or not)."""
        return [m for m in self.list_missions()
                if isinstance(m.get("schedule"), dict)]
