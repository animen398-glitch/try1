import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union


def now_ts() -> str:
    """Local wall-clock timestamp (seconds resolution) — the single source the
    project's SQLite stores stamp ``first_seen``/``last_seen``/event rows with."""
    return datetime.now().isoformat(timespec='seconds')


class SQLiteStore:
    """Базовый класс для локальных SQLite-хранилищ проекта.

    Инкапсулирует общие операции: создание директории, идемпотентную
    инициализацию схемы, **единый каркас версий/миграций**, транзакционное
    соединение и декодирование JSON-полей.

    Контракт версионирования (один паттерн на все сторы):

    * ``SCHEMA``         — DDL последней схемы (``CREATE TABLE IF NOT EXISTS``),
      безопасен на новой и на существующей БД.
    * ``SCHEMA_VERSION`` — целое; текущая версия схемы (по умолчанию 1).
    * ``MIGRATIONS``     — ``{target_version: fn(conn)}``; ``fn`` приводит БД с
      версии ``target_version - 1`` к ``target_version``. Применяются по
      возрастанию для всех ``current < target <= SCHEMA_VERSION`` ровно один
      раз (идемпотентность гарантирует ``PRAGMA user_version``), после чего
      версия проставляется. На пустой БД дата-миграции — no-op (нет строк);
      аддитивные ALTER используйте через идемпотентный :meth:`_add_column`.

    Понижение версии не выполняется: БД с версией выше ``SCHEMA_VERSION``
    остаётся как есть (forward-only, защита от отката кода на старую сборку).
    """

    SCHEMA: str = ''
    JSON_FIELDS: tuple = ('metadata',)
    SCHEMA_VERSION: int = 1
    MIGRATIONS: Dict[int, Callable[[sqlite3.Connection], None]] = {}

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            if self.SCHEMA:
                conn.executescript(self.SCHEMA)  # CREATE IF NOT EXISTS — idempotent
            self._apply_migrations(conn)

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        """Привести БД к ``SCHEMA_VERSION``, выполнив недостающие миграции по
        порядку, затем проставить версию. Никогда не понижает версию."""
        current = int(conn.execute('PRAGMA user_version').fetchone()[0])
        if current >= self.SCHEMA_VERSION:
            return  # уже актуальна или новее — не трогаем (forward-only)
        for target in sorted(self.MIGRATIONS):
            if current < target <= self.SCHEMA_VERSION:
                self.MIGRATIONS[target](conn)
        # ``PRAGMA`` не принимает плейсхолдеры; SCHEMA_VERSION приведён к int.
        conn.execute(f'PRAGMA user_version = {int(self.SCHEMA_VERSION)}')

    def schema_version(self) -> int:
        """Текущая версия схемы на диске (для диагностики/тестов)."""
        with self._connect() as conn:
            return int(conn.execute('PRAGMA user_version').fetchone()[0])

    @staticmethod
    def _add_column(conn: sqlite3.Connection, table: str, column_def: str) -> bool:
        """Идемпотентный ``ALTER TABLE ... ADD COLUMN``.

        Безопасен внутри миграции даже когда колонка уже есть (новая БД, где
        ``SCHEMA`` уже создала последнюю форму): добавляет только отсутствующую
        колонку. ``column_def`` = ``'имя ТИП [DEFAULT ...]'``. Возвращает True,
        если колонка была добавлена."""
        col = column_def.split()[0]
        existing = {r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()}
        if col in existing:
            return False
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {column_def}')
        return True

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
