"""Offline tests for the storage backend abstraction (Roadmap E7)."""

import sqlite3

import pytest

from utils.db_backend import (
    DatabaseBackend,
    PostgresBackend,
    SQLiteBackend,
    resolve_backend,
)
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


def test_resolve_postgres_returns_backend():
    for dsn in ("postgres://u@h/db", "postgresql://u@h/db"):
        b = resolve_backend(dsn)
        assert isinstance(b, PostgresBackend)
        assert b.dialect == "postgres" and b.placeholder == "%s"


def test_resolve_empty_is_error():
    with pytest.raises(ValueError):
        resolve_backend("")


# --- dialect ops (E7 increment 2) --------------------------------------------

def test_sqlite_build_upsert_matches_legacy_sql():
    b = SQLiteBackend(":memory:", wal=False)
    assert (b.build_upsert("kv", ["k", "v"], replace=True)
            == "INSERT OR REPLACE INTO kv (k,v) VALUES (?,?)")
    assert (b.build_upsert("kv", ["k", "v"], replace=False)
            == "INSERT INTO kv (k,v) VALUES (?,?)")


def test_sqlite_schema_version_roundtrip(tmp_path):
    b = SQLiteBackend(tmp_path / "v.db")
    conn = b.connect()
    try:
        b.prepare(conn)
        assert b.get_schema_version(conn) == 0
        b.set_schema_version(conn, 3)
        assert b.get_schema_version(conn) == 3
        conn.execute("CREATE TABLE t (a, b)")
        assert b.table_columns(conn, "t") == {"a", "b"}
    finally:
        conn.close()


def test_postgres_build_upsert_uses_on_conflict():
    b = PostgresBackend("postgres://x")
    assert (b.build_upsert("kv", ["id", "v"], replace=True)
            == "INSERT INTO kv (id,v) VALUES (%s,%s) "
               "ON CONFLICT (id) DO UPDATE SET v=EXCLUDED.v")
    # Explicit conflict key + a plain insert.
    assert b.build_upsert("t", ["a", "b"], replace=True, key_columns=["a"]) == (
        "INSERT INTO t (a,b) VALUES (%s,%s) "
        "ON CONFLICT (a) DO UPDATE SET b=EXCLUDED.b")
    assert (b.build_upsert("kv", ["id", "v"], replace=False)
            == "INSERT INTO kv (id,v) VALUES (%s,%s)")


def test_postgres_build_upsert_all_keys_do_nothing():
    b = PostgresBackend("postgres://x")
    assert (b.build_upsert("t", ["id"], replace=True, key_columns=["id"])
            == "INSERT INTO t (id) VALUES (%s) ON CONFLICT (id) DO NOTHING")


class _FakeCursor:
    def __init__(self, log, rows=None):
        self._log = log
        self._rows = rows or []

    def execute(self, sql, params=()):
        self._log.append((sql, tuple(params)))
        return self

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeRaw:
    """A minimal DB-API 2.0 connection double (no real Postgres)."""

    def __init__(self, rows=None):
        self.log = []
        self.committed = self.rolled_back = self.closed = False
        self._rows = rows or []

    def cursor(self):
        return _FakeCursor(self.log, self._rows)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_postgres_connect_wraps_driver_via_adapter():
    raw = _FakeRaw()
    b = PostgresBackend("postgres://h/db", connect_fn=lambda dsn: raw)
    conn = b.connect()
    conn.execute("SELECT 1", (5,))
    conn.commit()
    conn.close()
    assert raw.log == [("SELECT 1", (5,))]
    assert raw.committed and raw.closed


def test_postgres_table_columns_queries_information_schema():
    raw = _FakeRaw(rows=[("a",), ("b",)])
    b = PostgresBackend("postgres://h/db", connect_fn=lambda dsn: raw)
    conn = b.connect()
    assert b.table_columns(conn, "t") == {"a", "b"}
    sql, params = raw.log[-1]
    assert "information_schema.columns" in sql and params == ("t",)


def test_postgres_missing_driver_raises_clear_error():
    b = PostgresBackend("postgres://h/db")  # real lazy driver import
    try:
        import psycopg  # noqa: F401
        has_driver = True
    except ImportError:
        try:
            import psycopg2  # noqa: F401
            has_driver = True
        except ImportError:
            has_driver = False
    if has_driver:
        pytest.skip("a psycopg driver is installed; nothing to assert")
    with pytest.raises(RuntimeError, match="psycopg"):
        b.connect()


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
