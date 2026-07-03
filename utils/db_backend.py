"""Storage backend abstraction (Roadmap E7 — PostgreSQL readiness).

The project's stores all sit on :class:`utils.sqlite_store.SQLiteStore`, which
until now hard-coded ``sqlite3.connect`` and the SQLite dialect. This module
introduces the seam a future non-SQLite backend (PostgreSQL) plugs into, without
rewriting the stores: connection creation and per-connection dialect setup
(row factory + durability PRAGMAs) move behind a small :class:`DatabaseBackend`
interface. Today only :class:`SQLiteBackend` is implemented and it reproduces the
previous behaviour byte-for-byte; a Postgres DSN resolves to a documented
``NotImplementedError`` rather than silently misbehaving.

Offline, stdlib-only, no new dependency. The transaction semantics (commit /
rollback / close, and the leak-safe ordering) stay in ``SQLiteStore._connect`` —
the backend only owns *how a connection is created and prepared*, which is the
dialect-specific part.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Union


class DatabaseBackend:
    """Interface for a database backend: create + prepare a DB-API connection.

    Subclasses own the dialect-specific bits. ``placeholder`` is the parameter
    marker (``?`` for SQLite, ``%s`` for psycopg) and ``dialect`` a short name;
    both are exposed for a future increment that generates dialect-aware SQL. The
    store keeps ownership of the transaction lifecycle.
    """

    dialect: str = "base"
    placeholder: str = "?"
    supports_pragmas: bool = False

    def connect(self) -> Any:
        """Return a new raw DB-API connection (no dialect prep applied yet)."""
        raise NotImplementedError

    def prepare(self, conn: Any) -> None:
        """Apply per-connection dialect setup (row factory, PRAGMAs). Called by
        the store inside its transaction ``try`` so a failure still closes the
        connection."""

    def apply_pragmas(self, conn: Any) -> None:
        """Apply durability/concurrency PRAGMAs (SQLite); a no-op elsewhere."""

    # --- dialect ops (E7 increment 2) ----------------------------------------
    # The base store routes its generic operations through these so the dialect
    # lives in the backend, not in the store. Subclasses must implement them.

    def get_schema_version(self, conn: Any) -> int:
        """Read the store's schema version (SQLite: ``PRAGMA user_version``)."""
        raise NotImplementedError

    def set_schema_version(self, conn: Any, version: int) -> None:
        """Persist the store's schema version."""
        raise NotImplementedError

    def table_columns(self, conn: Any, table: str) -> set:
        """The set of column names of ``table`` (SQLite: ``PRAGMA table_info``)."""
        raise NotImplementedError

    def build_upsert(self, table: str, columns, *, replace: bool = True,
                     key_columns=None) -> str:
        """SQL for inserting a row, optionally replacing an existing one.

        ``columns`` are trusted (whitelisted by the caller against the live
        schema). ``key_columns`` name the conflict target for dialects that need
        it explicitly (Postgres ``ON CONFLICT``); SQLite's ``INSERT OR REPLACE``
        ignores it. Uses this backend's parameter :attr:`placeholder`.
        """
        raise NotImplementedError


class SQLiteBackend(DatabaseBackend):
    """SQLite backend — reproduces :class:`SQLiteStore`'s original connection.

    ``connect`` mirrors the old ``sqlite3.connect(str(path), timeout=…)`` (so a
    connect-time corruption raises exactly as before), and ``prepare`` applies
    the ``Row`` factory plus the durability PRAGMAs. ``wal`` / ``busy_timeout_ms``
    are the same knobs the store exposed as class attributes.
    """

    dialect = "sqlite"
    placeholder = "?"
    supports_pragmas = True

    def __init__(self, db_path: Union[str, Path], *,
                 busy_timeout_ms: int = 5000, wal: bool = True):
        self.db_path = str(db_path)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self.wal = bool(wal)

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=self.busy_timeout_ms / 1000)

    def apply_pragmas(self, conn: sqlite3.Connection) -> None:
        # Contract/rationale documented on SQLiteStore. PRAGMAs are safe no-fail;
        # busy_timeout + synchronous are per-connection, journal_mode=WAL is
        # persistent (a no-op on an already-WAL DB).
        conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
        conn.execute("PRAGMA synchronous = NORMAL")
        if self.wal:
            conn.execute("PRAGMA journal_mode = WAL")

    def prepare(self, conn: sqlite3.Connection) -> None:
        conn.row_factory = sqlite3.Row
        self.apply_pragmas(conn)

    # --- dialect ops --- (byte-identical to the store's original inline SQL) ---

    def get_schema_version(self, conn: sqlite3.Connection) -> int:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])

    def set_schema_version(self, conn: sqlite3.Connection, version: int) -> None:
        # PRAGMA takes no placeholder; version is coerced to int by the caller.
        conn.execute(f"PRAGMA user_version = {int(version)}")

    def table_columns(self, conn: sqlite3.Connection, table: str) -> set:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def build_upsert(self, table: str, columns, *, replace: bool = True,
                     key_columns=None) -> str:
        verb = "INSERT OR REPLACE" if replace else "INSERT"
        cols = list(columns)
        ph = ",".join([self.placeholder] * len(cols))
        return f'{verb} INTO {table} ({",".join(cols)}) VALUES ({ph})'


class _DBAPIConnectionAdapter:
    """Give a raw DB-API 2.0 connection (psycopg) the small surface the store
    calls on a connection: ``execute`` / ``executescript`` (which SQLite exposes
    on the connection but the DB-API defines on the cursor) plus the transaction
    lifecycle. Keeps :meth:`SQLiteStore._connect` dialect-agnostic."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw
        self.row_factory = None  # set by a backend's prepare() if it wants one

    def execute(self, sql: str, params=()):  # noqa: ANN001 - mirrors sqlite3
        cur = self._raw.cursor()
        cur.execute(sql, tuple(params) if params else ())
        return cur

    def executescript(self, sql: str):
        cur = self._raw.cursor()
        cur.execute(sql)
        return cur

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()


def _default_pg_connect(dsn: str) -> Any:
    """Open a real PostgreSQL connection via psycopg (v3) or psycopg2.

    Imported lazily so the driver is a soft optional dependency — absent it, a
    clear error is raised only when a Postgres DSN is actually used, never at
    import time. Never bundled into the ``.exe``.
    """
    try:
        import psycopg  # type: ignore
        return psycopg.connect(dsn)
    except ImportError:
        pass
    try:
        import psycopg2  # type: ignore
        return psycopg2.connect(dsn)
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL backend requires the 'psycopg' (v3) or 'psycopg2' driver; "
            "install one to use a postgres:// DSN") from exc


class PostgresBackend(DatabaseBackend):
    """PostgreSQL backend (E7 increment 2).

    Implements the full dialect surface (``%s`` placeholders, ``ON CONFLICT``
    upserts, ``information_schema`` introspection, and a metadata-table schema
    version, since Postgres has no ``PRAGMA user_version``). ``connect`` opens a
    real connection through the lazily-imported driver and wraps it in
    :class:`_DBAPIConnectionAdapter` so the store's connection API works. The
    driver import is injectable (``connect_fn``) for offline tests.

    Note: a store additionally needs its ``SCHEMA`` DDL and any bespoke SQL made
    dialect-aware, and a declared conflict key, before it runs fully on Postgres;
    this backend provides the dialect layer those build on.
    """

    dialect = "postgres"
    placeholder = "%s"
    supports_pragmas = False

    _VERSION_TABLE = "_asa_schema_version"

    def __init__(self, dsn: str, *, connect_fn=None):
        self.dsn = str(dsn)
        self._connect_fn = connect_fn or _default_pg_connect

    def connect(self) -> _DBAPIConnectionAdapter:
        return _DBAPIConnectionAdapter(self._connect_fn(self.dsn))

    def get_schema_version(self, conn: Any) -> int:
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {self._VERSION_TABLE} "
            "(version INTEGER NOT NULL)")
        row = conn.execute(f"SELECT version FROM {self._VERSION_TABLE} "
                           "LIMIT 1").fetchone()
        return int(row[0]) if row else 0

    def set_schema_version(self, conn: Any, version: int) -> None:
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {self._VERSION_TABLE} "
            "(version INTEGER NOT NULL)")
        conn.execute(f"DELETE FROM {self._VERSION_TABLE}")
        conn.execute(f"INSERT INTO {self._VERSION_TABLE} (version) VALUES (%s)",
                     (int(version),))

    def table_columns(self, conn: Any, table: str) -> set:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s", (table,)).fetchall()
        return {r[0] for r in rows}

    def build_upsert(self, table: str, columns, *, replace: bool = True,
                     key_columns=None) -> str:
        cols = list(columns)
        ph = ",".join([self.placeholder] * len(cols))
        stmt = f'INSERT INTO {table} ({",".join(cols)}) VALUES ({ph})'
        if not replace:
            return stmt
        keys = list(key_columns) if key_columns else ["id"]
        conflict = ",".join(keys)
        updates = ",".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in keys)
        if not updates:
            return f"{stmt} ON CONFLICT ({conflict}) DO NOTHING"
        return f"{stmt} ON CONFLICT ({conflict}) DO UPDATE SET {updates}"


def _strip_scheme(dsn: str) -> str:
    body = dsn.split("://", 1)[1] if "://" in dsn else dsn
    # sqlite:///abs/path leaves a leading '/'; sqlite://rel/path leaves 'rel/path'.
    return body


def resolve_backend(dsn: Union[str, Path], *,
                    busy_timeout_ms: int = 5000,
                    wal: bool = True) -> DatabaseBackend:
    """Resolve a data-source name to a backend (E7 factory).

    Accepts a bare filesystem path, ``sqlite:///path`` / ``sqlite://path``, or
    ``:memory:`` → a :class:`SQLiteBackend`. A ``postgres://`` / ``postgresql://``
    DSN → a :class:`PostgresBackend` (E7 increment 2); the driver is imported
    lazily only when it actually connects. An empty DSN is an error.
    """
    if isinstance(dsn, Path):
        return SQLiteBackend(dsn, busy_timeout_ms=busy_timeout_ms, wal=wal)
    text = str(dsn or "").strip()
    if not text:
        raise ValueError("empty database DSN")
    lower = text.lower()
    if lower.startswith(("postgres://", "postgresql://")):
        return PostgresBackend(text)
    if lower.startswith("sqlite:"):
        path = _strip_scheme(text)
        # sqlite://:memory: / sqlite:///:memory: → in-memory (no WAL sidecars).
        if path.strip("/") == ":memory:":
            return SQLiteBackend(":memory:", busy_timeout_ms=busy_timeout_ms, wal=False)
        return SQLiteBackend(path, busy_timeout_ms=busy_timeout_ms, wal=wal)
    if text == ":memory:":
        return SQLiteBackend(":memory:", busy_timeout_ms=busy_timeout_ms, wal=False)
    # A bare filesystem path.
    return SQLiteBackend(text, busy_timeout_ms=busy_timeout_ms, wal=wal)
