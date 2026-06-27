"""Tests for the durability/concurrency contract of ``utils.sqlite_store``.

Offline, no network, no sleeps/threads — concurrency is exercised with two
plain connections to the same file DB so the assertions stay deterministic.
"""
import sqlite3

import pytest

from utils.sqlite_store import SQLiteStore


class _Store(SQLiteStore):
    """Minimal concrete store for exercising the base contract."""

    SCHEMA = 'CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, v TEXT)'

    def add(self, v: str) -> None:
        with self._connect() as conn:
            conn.execute('INSERT INTO items (v) VALUES (?)', (v,))

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute('SELECT COUNT(*) FROM items').fetchone()[0])


@pytest.fixture()
def store(tmp_path):
    return _Store(tmp_path / 'sub' / 'items.db')


def test_wal_enabled_after_init(store):
    """``journal_mode=WAL`` is persisted on the DB by construction."""
    with store._connect() as conn:
        mode = conn.execute('PRAGMA journal_mode').fetchone()[0]
    assert str(mode).lower() == 'wal'


def test_connection_pragmas_applied(store):
    """Every connection carries the durability/concurrency PRAGMA."""
    with store._connect() as conn:
        busy = int(conn.execute('PRAGMA busy_timeout').fetchone()[0])
        sync = int(conn.execute('PRAGMA synchronous').fetchone()[0])
    assert busy == _Store.BUSY_TIMEOUT_MS
    assert sync == 1  # NORMAL


def test_busy_timeout_tracks_constant(tmp_path):
    """``BUSY_TIMEOUT_MS`` is the single source for the connect timeout + PRAGMA."""
    class _FastStore(_Store):
        BUSY_TIMEOUT_MS = 1234

    s = _FastStore(tmp_path / 'fast.db')
    with s._connect() as conn:
        assert int(conn.execute('PRAGMA busy_timeout').fetchone()[0]) == 1234


def test_wal_opt_out(tmp_path):
    """``WAL=False`` keeps the default rollback journal (opt-out path)."""
    class _NoWal(_Store):
        WAL = False

    s = _NoWal(tmp_path / 'nowal.db')
    with s._connect() as conn:
        mode = str(conn.execute('PRAGMA journal_mode').fetchone()[0]).lower()
    assert mode != 'wal'


def test_reader_not_blocked_by_active_writer(store):
    """Under WAL a reader sees the last committed snapshot while another
    connection holds an open write transaction — no ``database is locked``."""
    store.add('first')  # one committed row

    writer = sqlite3.connect(str(store.db_path))
    reader = sqlite3.connect(str(store.db_path))
    reader.execute(f'PRAGMA busy_timeout = {store.BUSY_TIMEOUT_MS}')
    try:
        # Hold an uncommitted write lock on the DB.
        writer.execute('BEGIN IMMEDIATE')
        writer.execute("INSERT INTO items (v) VALUES ('pending')")

        # WAL: the reader proceeds against the committed snapshot (count == 1).
        # Without WAL this SELECT would block on the writer and time out.
        count = int(reader.execute('SELECT COUNT(*) FROM items').fetchone()[0])
        assert count == 1
    finally:
        writer.rollback()
        writer.close()
        reader.close()


def test_roundtrip_still_works(store):
    """Schema/migration/JSON plumbing is unaffected by the PRAGMA change."""
    store.add('a')
    store.add('b')
    assert store.count() == 2
    assert store.schema_version() == _Store.SCHEMA_VERSION


# ── resilience: corrupt DB / malformed JSON ────────────────────────────────


class _JsonStore(SQLiteStore):
    SCHEMA = 'CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, meta TEXT)'
    JSON_FIELDS = ('meta',)


def test_corrupt_db_quarantined_and_recreated(tmp_path):
    """A garbage DB file does not crash construction: it is quarantined and a
    fresh, working store is recreated; the original bytes are preserved."""
    db = tmp_path / 'items.db'
    db.write_bytes(b'this is definitely not a sqlite database file')

    store = _Store(db)  # must not raise
    store.add('x')
    assert store.count() == 1  # fresh DB works

    quarantined = list(tmp_path.glob('items.db.corrupt-*'))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b'this is definitely not a sqlite database file'


def test_is_corruption_classification():
    """Corruption markers are recognized; a transient lock never is."""
    assert _Store._is_corruption(sqlite3.DatabaseError('file is not a database'))
    assert _Store._is_corruption(sqlite3.DatabaseError('database disk image is malformed'))
    assert not _Store._is_corruption(sqlite3.OperationalError('database is locked'))
    assert not _Store._is_corruption(sqlite3.DatabaseError('some unrelated error'))


def test_corruption_optout_reraises(tmp_path):
    """``QUARANTINE_CORRUPT=False`` keeps the hard failure (opt-out)."""
    class _Strict(_Store):
        QUARANTINE_CORRUPT = False

    db = tmp_path / 'strict.db'
    db.write_bytes(b'not a sqlite database')
    with pytest.raises(sqlite3.DatabaseError):
        _Strict(db)


def test_malformed_json_field_left_raw(tmp_path):
    """A malformed JSON field degrades softly — the raw string is kept."""
    store = _JsonStore(tmp_path / 'json.db')
    with store._connect() as conn:
        row = conn.execute("SELECT 1 AS id, '{not json' AS meta").fetchone()
    decoded = _JsonStore._row_to_dict(row)
    assert decoded['meta'] == '{not json'
