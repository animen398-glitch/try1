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
    DSN raises :class:`NotImplementedError` — the documented seam where a future
    Postgres backend is wired in. An empty DSN is an error.
    """
    if isinstance(dsn, Path):
        return SQLiteBackend(dsn, busy_timeout_ms=busy_timeout_ms, wal=wal)
    text = str(dsn or "").strip()
    if not text:
        raise ValueError("empty database DSN")
    lower = text.lower()
    if lower.startswith(("postgres://", "postgresql://")):
        raise NotImplementedError(
            "PostgreSQL backend is not implemented yet (E7 seam); "
            "use a SQLite path or sqlite:// DSN")
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
