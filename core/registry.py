import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT    NOT NULL,
    data_type   TEXT    NOT NULL,
    content     TEXT,
    metadata    TEXT,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_data_type ON records (data_type);
CREATE INDEX IF NOT EXISTS idx_records_source    ON records (source);
"""


class DataRegistry:
    """Центральное хранилище записей проекта на SQLite (data/registry.db)."""

    def __init__(self, db_path: Union[str, Path] = 'data/registry.db'):
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

    def add_record(self, source: str, data_type: str, content: Any,
                   metadata: Optional[Dict[str, Any]] = None) -> int:
        """Сохранить запись. content сериализуется в JSON, если это не строка."""
        if isinstance(content, str) or content is None:
            stored_content = content
        else:
            stored_content = json.dumps(content, ensure_ascii=False)

        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO records
                   (source, data_type, content, metadata, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (source, data_type, stored_content,
                 json.dumps(metadata, ensure_ascii=False) if metadata is not None else None,
                 datetime.now().isoformat()),
            )
            return cur.lastrowid

    def get_records(self, data_type: Optional[str] = None,
                    source: Optional[str] = None,
                    limit: int = 1000) -> List[Dict[str, Any]]:
        """Вернуть записи с опциональной фильтрацией, новые сверху."""
        clauses, params = [], []
        if data_type is not None:
            clauses.append('data_type = ?')
            params.append(data_type)
        if source is not None:
            clauses.append('source = ?')
            params.append(source)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT * FROM records {where} ORDER BY id DESC LIMIT ?',
                params,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_record(self, record_id: int) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM records WHERE id = ?', (record_id,),
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def count(self, data_type: Optional[str] = None) -> int:
        with self._connect() as conn:
            if data_type is None:
                row = conn.execute('SELECT COUNT(*) AS n FROM records').fetchone()
            else:
                row = conn.execute(
                    'SELECT COUNT(*) AS n FROM records WHERE data_type = ?',
                    (data_type,),
                ).fetchone()
            return row['n']

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        if data.get('metadata'):
            try:
                data['metadata'] = json.loads(data['metadata'])
            except (ValueError, TypeError):
                pass
        return data
