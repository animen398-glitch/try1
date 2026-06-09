import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional, Union


class SQLiteStore:
    """Базовый класс для локальных SQLite-хранилищ проекта.

    Инкапсулирует общие операции: создание директории, идемпотентную
    инициализацию схемы, транзакционное соединение и декодирование JSON-полей.
    Подклассы задают ``SCHEMA`` (DDL) и при необходимости ``JSON_FIELDS``.
    """

    SCHEMA: str = ''
    JSON_FIELDS: tuple = ('metadata',)

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        if self.SCHEMA:
            with self._connect() as conn:
                conn.executescript(self.SCHEMA)

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

    @classmethod
    def _row_to_dict(cls, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        data = dict(row)
        for field in cls.JSON_FIELDS:
            if data.get(field):
                try:
                    data[field] = json.loads(data[field])
                except (ValueError, TypeError):
                    pass
        return data
