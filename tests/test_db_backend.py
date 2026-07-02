"""Offline tests for the storage backend abstraction (Roadmap E7)."""

import sqlite3

import pytest

from utils.db_backend import DatabaseBackend, SQLiteBackend, resolve_backend
from utils.sqlite_store import SQLiteStore


# --- SQLiteBackend -----------------------------------------------------------

def test_backend_metadata():
    b = SQLiteBackend(":memory:", wal=False)
    assert b.dialect == "sqlite"
    assert b.placeholder == "?"
    assert b.supports_pragmas is True


def test_connect_and_prepare(tmp_path):
    b = SQLiteBackend(tmp_path / "t.db")
    conn = b.connect()
    try:
        b.prepare(conn)
        assert conn.row_factory is sqlite3.Row
        # WAL applied for a file DB.
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        conn.execute("CREATE TABLE x (a)")
        conn.execute("INSERT INTO x VALUES (1)")
        assert conn.execute("SELECT a FROM x").fetchone()["a"] == 1
    finally:
        conn.close()


def test_wal_can_be_disabled(tmp_path):
    b = SQLiteBackend(tmp_path / "n.db", wal=False)
    conn = b.connect()
    try:
        b.prepare(conn)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() != "wal"
    finally:
        conn.close()


# --- resolve_backend (DSN factory) -------------------------------------------

def test_resolve_bare_path(tmp_path):
    b = resolve_backend(str(tmp_path / "a.db"))
    assert isinstance(b, SQLiteBackend)
    assert b.wal is True


def test_resolve_path_object(tmp_path):
    assert isinstance(resolve_backend(tmp_path / "b.db"), SQLiteBackend)


def test_resolve_sqlite_scheme():
    assert isinstance(resolve_backend("sqlite://data/x.db"), SQLiteBackend)


def test_resolve_memory_disables_wal():
    for dsn in (":memory:", "sqlite://:memory:", "sqlite:///:memory:"):
        b = resolve_backend(dsn)
        assert isinstance(b, SQLiteBackend)
        assert b.wal is False


def test_resolve_postgres_is_documented_seam():
    for dsn in ("postgres://u@h/db", "postgresql://u@h/db"):
        with pytest.raises(NotImplementedError):
            resolve_backend(dsn)


def test_resolve_empty_is_error():
    with pytest.raises(ValueError):
        resolve_backend("")


# --- SQLiteStore routes through the backend ----------------------------------

class _TinyStore(SQLiteStore):
    SCHEMA = "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)"

    def put(self, k, v):
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)", (k, v))

    def get(self, k):
        with self._connect() as conn:
            row = conn.execute("SELECT v FROM kv WHERE k = ?", (k,)).fetchone()
            return row["v"] if row else None


def test_store_uses_default_sqlite_backend(tmp_path):
    store = _TinyStore(tmp_path / "s.db")
    assert isinstance(store._backend, SQLiteBackend)
    store.put("a", "1")
    assert store.get("a") == "1"
    assert store.schema_version() == store.SCHEMA_VERSION


def test_store_accepts_injected_backend(tmp_path):
    backend = SQLiteBackend(tmp_path / "inj.db")
    store = _TinyStore(tmp_path / "ignored.db", backend=backend)
    assert store._backend is backend
    store.put("x", "y")
    assert store.get("x") == "y"


def test_apply_pragmas_delegates_to_backend(tmp_path):
    store = _TinyStore(tmp_path / "p.db")
    conn = store._backend.connect()
    try:
        store._apply_pragmas(conn)  # public method preserved, delegates to backend
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()


def test_injected_base_backend_would_need_connect():
    # A bare DatabaseBackend does not implement connect (interface only).
    with pytest.raises(NotImplementedError):
        DatabaseBackend().connect()
