"""core/engagement_store.py
Persistent store for Pentest Engagements (Engagement & ROE Foundation, F2).

Storage for engagement payloads, not a second findings/asset/timeline source: the
canonical export remains the JSON produced by
:func:`core.engagement.engagement_to_json` and validated by
``asa_engagement.schema.json``. Mirrors :class:`core.mission_store.MissionStore` —
single-table (an engagement carries no event log in the F1 contract), so it
declares an events-less ``PROJECT_EXPORT`` and the faithful project slice is just
the engagement rows. No second store of the entities it links; it only persists
the engagement envelope.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.config import get_path_manager
from core.engagement import engagement_to_json
from utils.sqlite_store import SQLiteStore, now_ts as _now


def _default_db_path() -> Path:
    return get_path_manager().get_db_path("engagements.db")


ENGAGEMENTS_DB = _default_db_path()


class EngagementStore(SQLiteStore):
    """SQLite-backed persistence for engagements (single table, no event log)."""

    JSON_FIELDS = ("payload",)
    # Single-table project slice: engagement rows only (events_table=None).
    PROJECT_EXPORT = ("engagements", None, None)
    SCHEMA_VERSION = 1

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS engagements (
        id         TEXT PRIMARY KEY,
        client     TEXT NOT NULL,
        project    TEXT NOT NULL,
        profile    TEXT NOT NULL,
        status     TEXT NOT NULL,
        payload    TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_engagements_project
        ON engagements(project, updated_at);
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or ENGAGEMENTS_DB)

    @staticmethod
    def _payload_json(engagement: Dict[str, Any]) -> Dict[str, Any]:
        # Normalizes + schema-validates (asa_engagement) before any write.
        return engagement_to_json(engagement)

    def save_engagement(self, engagement: Dict[str, Any], *,
                        now: Optional[str] = None) -> Dict[str, Any]:
        """Insert or replace one engagement by ``engagement_id``.

        Duplicate saves are idempotent: the existing ``created_at`` is preserved
        while client/project/status/payload/updated_at move to the latest
        canonical payload."""
        payload = self._payload_json(engagement)
        engagement_id = str(payload.get("engagement_id") or "").strip()
        client = str(payload.get("client") or "").strip()
        project = str(payload.get("project") or "").strip()
        profile = str(payload.get("profile") or "client_safe").strip()
        status = str(payload.get("status") or "").strip()
        if not engagement_id:
            raise ValueError("engagement_id is required")
        if not client:
            raise ValueError("client is required")
        if not project:
            raise ValueError("project is required")
        stamp = now or _now()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
            created_at = existing["created_at"] if existing is not None else stamp
            conn.execute(
                "INSERT INTO engagements"
                " (id, client, project, profile, status, payload,"
                "  created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " client = excluded.client,"
                " project = excluded.project,"
                " profile = excluded.profile,"
                " status = excluded.status,"
                " payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (engagement_id, client, project, profile, status, encoded,
                 created_at, stamp),
            )
            row = conn.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def get_engagement(self, engagement_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM engagements WHERE id = ?", (str(engagement_id),)
            ).fetchone()
        return self._row_to_dict(row)

    def list_engagements(self, project: Optional[str] = None
                         ) -> List[Dict[str, Any]]:
        params: list = []
        where = ""
        if project is not None:
            where = " WHERE project = ?"
            params.append(project)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM engagements{where}"
                " ORDER BY updated_at DESC, id DESC",
                params,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_engagement(self, engagement_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM engagements WHERE id = ?", (str(engagement_id),)
            )
        return bool(cur.rowcount)

    def export_engagement(self, engagement_id: str) -> Dict[str, Any]:
        row = self.get_engagement(engagement_id)
        if row is None:
            raise KeyError(engagement_id)
        return engagement_to_json(row["payload"])
