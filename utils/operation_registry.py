import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from utils.sqlite_store import SQLiteStore


class OperationRegistry(SQLiteStore):
    """Реестр истории операций на SQLite (recon/bypass/capture/analysis)."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS operations (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        target       TEXT    NOT NULL,
        phase        TEXT    NOT NULL,
        status       TEXT    NOT NULL DEFAULT 'pending',
        started_at   TEXT    NOT NULL,
        finished_at  TEXT,
        duration_ms  INTEGER,
        output_dir   TEXT,
        error        TEXT,
        metadata     TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_operations_target ON operations (target);
    CREATE INDEX IF NOT EXISTS idx_operations_phase  ON operations (phase);
    CREATE INDEX IF NOT EXISTS idx_operations_status ON operations (status);
    """

    # Bounded history so the audit log can't grow forever on a long-lived install:
    # keep the newest ``MAX_HISTORY`` operations, pruning every ``PRUNE_EVERY``
    # inserts (amortized — no COUNT per write). Only this operational audit log is
    # bounded; the DataRegistry's user-collected records are never auto-pruned
    # (it exposes an explicit ``clear()`` instead).
    MAX_HISTORY: int = 5000
    PRUNE_EVERY: int = 200

    def __init__(self, db_path: Union[str, Path] = None):
        # Default through PathManager (via core.config) instead of a CWD-relative
        # 'operations.db', mirroring DataRegistry -> REGISTRY_DB, so a frozen .exe
        # resolves the DB under %APPDATA% even when no path is passed explicitly.
        if db_path is None:
            from core.config import OPERATIONS_DB
            db_path = str(OPERATIONS_DB)
        super().__init__(db_path)

    def start(self, target: str, phase: str,
              output_dir: Optional[str] = None,
              metadata: Optional[Dict[str, Any]] = None) -> int:
        """Записать начало операции, вернуть её id."""
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO operations
                   (target, phase, status, started_at, output_dir, metadata)
                   VALUES (?, ?, 'running', ?, ?, ?)""",
                (target, phase, datetime.now().isoformat(), output_dir,
                 json.dumps(metadata, ensure_ascii=False, default=str)
                 if metadata is not None else None),
            )
            op_id = cur.lastrowid
            # Self-bound the log in the same transaction, amortized over inserts.
            if self.PRUNE_EVERY and op_id % self.PRUNE_EVERY == 0:
                self._prune(conn, self.MAX_HISTORY)
            return op_id

    def finish(self, operation_id: int, status: str = 'success',
               error: Optional[str] = None,
               metadata: Optional[Dict[str, Any]] = None) -> None:
        """Закрыть операцию, рассчитать длительность по started_at."""
        with self._connect() as conn:
            row = conn.execute(
                'SELECT started_at FROM operations WHERE id = ?',
                (operation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f'operation {operation_id} not found')

            finished = datetime.now()
            started = datetime.fromisoformat(row['started_at'])
            duration_ms = int((finished - started).total_seconds() * 1000)

            if metadata is None:
                conn.execute(
                    """UPDATE operations
                       SET status = ?, finished_at = ?, duration_ms = ?, error = ?
                       WHERE id = ?""",
                    (status, finished.isoformat(), duration_ms, error, operation_id),
                )
            else:
                conn.execute(
                    """UPDATE operations
                       SET status = ?, finished_at = ?, duration_ms = ?, error = ?,
                           metadata = ?
                       WHERE id = ?""",
                    (status, finished.isoformat(), duration_ms, error,
                     json.dumps(metadata, ensure_ascii=False, default=str), operation_id),
                )

    def get(self, operation_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM operations WHERE id = ?', (operation_id,),
            ).fetchone()
            return self._row_to_dict(row)

    def history(self, target: Optional[str] = None,
                phase: Optional[str] = None,
                status: Optional[str] = None,
                limit: int = 100) -> List[Dict[str, Any]]:
        """История операций с опциональной фильтрацией, новые сверху."""
        clauses, params = [], []
        if target is not None:
            clauses.append('target = ?')
            params.append(target)
        if phase is not None:
            clauses.append('phase = ?')
            params.append(phase)
        if status is not None:
            clauses.append('status = ?')
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT * FROM operations {where} ORDER BY id DESC LIMIT ?',
                params,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def prune(self, max_rows: Optional[int] = None) -> int:
        """Drop the oldest operations, keeping the newest ``max_rows`` (default
        :attr:`MAX_HISTORY`). Returns the number of rows deleted. For explicit
        maintenance; ``start`` also prunes automatically. Bounds only this
        operational audit log — never the DataRegistry's user-collected data."""
        with self._connect() as conn:
            return self._prune(
                conn, max_rows if max_rows is not None else self.MAX_HISTORY)

    @staticmethod
    def _prune(conn, max_rows: int) -> int:
        """``prune`` body over an open connection (keep newest ``max_rows`` by id)."""
        cur = conn.execute(
            'DELETE FROM operations WHERE id NOT IN '
            '(SELECT id FROM operations ORDER BY id DESC LIMIT ?)',
            (max(int(max_rows), 0),))
        return cur.rowcount
