import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


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


class OperationRegistry:
    """Реестр истории операций на SQLite (recon/bypass/capture/analysis)."""

    def __init__(self, db_path: Union[str, Path] = 'operations.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

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
                 json.dumps(metadata) if metadata is not None else None),
            )
            return cur.lastrowid

    def finish(self, operation_id: int, status: str = 'success',
               error: Optional[str] = None) -> None:
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

            conn.execute(
                """UPDATE operations
                   SET status = ?, finished_at = ?, duration_ms = ?, error = ?
                   WHERE id = ?""",
                (status, finished.isoformat(), duration_ms, error, operation_id),
            )

    def get(self, operation_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM operations WHERE id = ?', (operation_id,),
            ).fetchone()
            return self._row_to_dict(row) if row else None

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

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        if data.get('metadata'):
            try:
                data['metadata'] = json.loads(data['metadata'])
            except (ValueError, TypeError):
                pass
        return data
