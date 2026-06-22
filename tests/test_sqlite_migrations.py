"""Unified SQLite migration framework (F0.T1).

The base ``SQLiteStore`` carries one ``SCHEMA_VERSION`` / ``MIGRATIONS`` pattern:
idempotent ``CREATE IF NOT EXISTS`` schema + numbered, forward-only migrations
guarded by ``PRAGMA user_version``. These tests exercise the framework directly
on throwaway subclasses; the real stores (findings/asset/cve) keep their own
behaviour tests. No network.
"""

import sqlite3

from utils.sqlite_store import SQLiteStore

_T = 'CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY);'


def _seed(db, version=None, *, with_note=False):
    """Write a hand-shaped DB at a given user_version (None = leave default 0)."""
    cols = 'id INTEGER PRIMARY KEY' + (', note TEXT' if with_note else '')
    with sqlite3.connect(str(db)) as conn:
        conn.execute(f'CREATE TABLE t ({cols})')
        if version is not None:
            conn.execute(f'PRAGMA user_version = {version}')


def test_fresh_db_stamps_current_version(tmp_path):
    class S(SQLiteStore):
        SCHEMA = _T
        SCHEMA_VERSION = 3

    assert S(tmp_path / 'x.db').schema_version() == 3


def test_default_version_is_one_without_migrations(tmp_path):
    class S(SQLiteStore):
        SCHEMA = _T

    assert S(tmp_path / 'x.db').schema_version() == 1


def test_upgrade_runs_pending_migrations_in_order(tmp_path):
    calls = []

    class S(SQLiteStore):
        SCHEMA = _T
        SCHEMA_VERSION = 3
        MIGRATIONS = {
            1: lambda conn: calls.append(1),
            2: lambda conn: calls.append(2),
            3: lambda conn: calls.append(3),
        }

    db = tmp_path / 'x.db'
    _seed(db, version=0)
    s = S(db)
    assert calls == [1, 2, 3]          # ascending, all pending applied
    assert s.schema_version() == 3


def test_partial_upgrade_skips_already_applied(tmp_path):
    calls = []

    class S(SQLiteStore):
        SCHEMA = _T
        SCHEMA_VERSION = 3
        MIGRATIONS = {
            2: lambda conn: calls.append(2),
            3: lambda conn: calls.append(3),
        }

    db = tmp_path / 'x.db'
    _seed(db, version=2)               # already at v2
    s = S(db)
    assert calls == [3]                # only the v3 step runs
    assert s.schema_version() == 3


def test_migration_is_idempotent_across_reopen(tmp_path):
    calls = []

    class S(SQLiteStore):
        SCHEMA = _T
        SCHEMA_VERSION = 2
        MIGRATIONS = {2: lambda conn: calls.append(2)}

    db = tmp_path / 'x.db'
    S(db)                              # fresh → migration runs once, stamps 2
    S(db)                             # reopen at 2 → no migration
    assert calls == [2]


def test_never_downgrades(tmp_path):
    class S(SQLiteStore):
        SCHEMA = _T
        SCHEMA_VERSION = 2
        MIGRATIONS = {2: lambda conn: (_ for _ in ()).throw(
            AssertionError('must not run on a newer DB'))}

    db = tmp_path / 'x.db'
    _seed(db, version=5)              # ahead of the code's SCHEMA_VERSION
    s = S(db)
    assert s.schema_version() == 5    # left as-is, migration not invoked


def test_add_column_is_idempotent(tmp_path):
    db = tmp_path / 'x.db'
    _seed(db, version=1)
    with sqlite3.connect(str(db)) as conn:
        assert SQLiteStore._add_column(conn, 't', 'note TEXT') is True
        assert SQLiteStore._add_column(conn, 't', 'note TEXT') is False
        cols = {r[1] for r in conn.execute('PRAGMA table_info(t)')}
    assert cols == {'id', 'note'}


def test_add_column_migration_safe_on_existing_and_fresh(tmp_path):
    class S(SQLiteStore):
        # latest schema includes the column; CREATE IF NOT EXISTS won't add it to
        # an existing table, so the migration must.
        SCHEMA = 'CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, note TEXT);'
        SCHEMA_VERSION = 2
        MIGRATIONS = {2: lambda conn: SQLiteStore._add_column(conn, 't', 'note TEXT')}

    # existing v1 DB without the column → migration adds it.
    existing = tmp_path / 'existing.db'
    _seed(existing, version=1)        # table t WITHOUT note
    s = S(existing)
    with sqlite3.connect(str(existing)) as conn:
        cols = {r[1] for r in conn.execute('PRAGMA table_info(t)')}
    assert 'note' in cols and s.schema_version() == 2

    # fresh DB already has the column from SCHEMA → migration is a no-op (no crash).
    fresh = S(tmp_path / 'fresh.db')
    assert fresh.schema_version() == 2
