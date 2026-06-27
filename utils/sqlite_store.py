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

    Долговечность/конкурентность (один контракт на все сторы): каждое
    соединение открывается с durability-PRAGMA (:meth:`_apply_pragmas`).
    ``journal_mode=WAL`` (persistent) позволяет читателям работать, пока
    писатель держит блокировку — это убирает ``database is locked`` при
    одновременной записи monitor-треда и чтении GUI/web-консоли из одного
    стора. ``synchronous=NORMAL`` устойчив к крашу приложения; потеряться может
    лишь последняя транзакция при сбое ОС/питания (приемлемо для локальной
    аналитики, не финданных). ``busy_timeout`` заставляет конкурирующего
    писателя подождать, а не падать сразу. WAL создаёт сайдкары ``-wal``/
    ``-shm`` рядом с ``.db``; они восстанавливаются SQLite при открытии, а сырой
    файл БД в проекте нигде не копируется (export/import — построчный, см.
    :attr:`PROJECT_EXPORT`), поэтому на бэкап/упаковку это не влияет.
    """

    SCHEMA: str = ''
    JSON_FIELDS: tuple = ('metadata',)
    SCHEMA_VERSION: int = 1
    MIGRATIONS: Dict[int, Callable[[sqlite3.Connection], None]] = {}
    # Stores whose rows are scoped by a ``project`` column opt into project-scoped
    # export/import (used by project bundles, core.project_io) by declaring
    # ``(main_table, events_table, events_fk_column)``. The faithful slice is the
    # main rows plus their event rows — ids/status/timestamps preserved verbatim.
    PROJECT_EXPORT: Optional[tuple] = None
    # Durability/concurrency knobs (see class docstring + :meth:`_apply_pragmas`).
    # ``WAL=False`` lets a store opt out (e.g. ``:memory:``); ``BUSY_TIMEOUT_MS``
    # is the single source for both the connect timeout and ``PRAGMA busy_timeout``.
    WAL: bool = True
    BUSY_TIMEOUT_MS: int = 5000

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

    def _apply_pragmas(self, conn: sqlite3.Connection) -> None:
        """Durability/concurrency PRAGMA, применяемые к каждому соединению.
        Контракт и обоснование — в docstring класса. ``busy_timeout`` и
        ``synchronous`` per-connection; ``journal_mode=WAL`` persistent (no-op на
        уже-WAL БД). Никогда не роняет соединение (PRAGMA — безопасные no-fail)."""
        conn.execute(f'PRAGMA busy_timeout = {int(self.BUSY_TIMEOUT_MS)}')
        conn.execute('PRAGMA synchronous = NORMAL')
        if self.WAL:
            conn.execute('PRAGMA journal_mode = WAL')

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=self.BUSY_TIMEOUT_MS / 1000)
        conn.row_factory = sqlite3.Row
        self._apply_pragmas(conn)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── project-scoped export / import (faithful row+event slice) ──────────────

    def _project_export_spec(self) -> tuple:
        if not self.PROJECT_EXPORT:
            raise NotImplementedError(
                f'{type(self).__name__} does not declare PROJECT_EXPORT')
        return self.PROJECT_EXPORT

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str) -> set:
        return {r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()}

    @staticmethod
    def _insert_rows(conn: sqlite3.Connection, table: str, rows, *,
                     allowed: set, replace: bool = True) -> int:
        """Insert raw row dicts verbatim. Column names are whitelisted against
        the live table schema (``allowed``) so an untrusted import bundle can
        never inject SQL via crafted keys. Table name comes from a trusted class
        attr (PROJECT_EXPORT), never user input."""
        verb = 'INSERT OR REPLACE' if replace else 'INSERT'
        n = 0
        for r in rows:
            cols = [c for c in r.keys() if c in allowed]
            if not cols:
                continue
            ph = ','.join('?' * len(cols))
            conn.execute(
                f'{verb} INTO {table} ({",".join(cols)}) VALUES ({ph})',
                [r[c] for c in cols])
            n += 1
        return n

    def export_project(self, project: str) -> Dict[str, Any]:
        """The project's rows + their event rows (raw column values, JSON fields
        left encoded so import is byte-faithful). Empty lists if none."""
        main, ev_tbl, fk = self._project_export_spec()
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(
                f'SELECT * FROM {main} WHERE project = ?', (project,)).fetchall()]
            ids = [r['id'] for r in rows]
            events = []
            if ids:
                ph = ','.join('?' * len(ids))
                events = [dict(r) for r in conn.execute(
                    f'SELECT * FROM {ev_tbl} WHERE {fk} IN ({ph})', ids).fetchall()]
        return {'rows': rows, 'events': events}

    def import_project(self, project: str, payload: Dict[str, Any], *,
                       replace: bool = False) -> Dict[str, Any]:
        """Insert an exported slice for ``project``. If the project already has
        rows: skipped unless ``replace`` (then its rows+events are deleted first).
        Event ``id`` (autoincrement) is dropped so it re-generates locally."""
        main, ev_tbl, fk = self._project_export_spec()
        rows = payload.get('rows') or []
        events = payload.get('events') or []
        with self._connect() as conn:
            existing = conn.execute(
                f'SELECT COUNT(*) FROM {main} WHERE project = ?',
                (project,)).fetchone()[0]
            if existing and not replace:
                return {'imported': 0, 'events': 0, 'skipped': True,
                        'reason': 'project exists'}
            if existing:
                old = [r[0] for r in conn.execute(
                    f'SELECT id FROM {main} WHERE project = ?', (project,)).fetchall()]
                if old:
                    ph = ','.join('?' * len(old))
                    conn.execute(f'DELETE FROM {ev_tbl} WHERE {fk} IN ({ph})', old)
                conn.execute(f'DELETE FROM {main} WHERE project = ?', (project,))
            main_cols = self._columns(conn, main)
            ev_cols = self._columns(conn, ev_tbl)
            n = self._insert_rows(conn, main, rows, allowed=main_cols)
            ev_no_id = [{k: v for k, v in e.items() if k != 'id'} for e in events]
            ne = self._insert_rows(conn, ev_tbl, ev_no_id, allowed=ev_cols,
                                   replace=False)
        return {'imported': n, 'events': ne, 'skipped': False}

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
