"""v1→v2 migration of the findings store (B fix).

v1 keyed findings by the bare, project-agnostic fingerprint; v2 keys them by the
project-scoped id (scoped_id(project, fingerprint)). Opening a v1 DB must re-key
every finding (and its events) in place, without data loss, and be idempotent.
No network.
"""

import sqlite3

from core.finding_fingerprint import fingerprint, scoped_id
from core.findings_store import FindingsStore


def _seed_v1_db(path, project='a.com'):
    """Write a v1-shaped findings DB: one finding keyed by the bare fingerprint
    plus a CREATED event, with user_version = 1."""
    fp = fingerprint('dns', 'spf')                 # location-less → bare key
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(FindingsStore.SCHEMA)
        conn.execute(
            'INSERT INTO findings (id, project, category, rule_id, title,'
            ' severity, status, evidence, first_seen_at, last_seen_at,'
            ' updated_at, status_source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            (fp, project, 'dns', 'spf', 'No SPF record', 'medium', 'IGNORED',
             None, '2026-01-01', '2026-01-01', '2026-01-01', 'user'))
        conn.execute(
            'INSERT INTO finding_events (finding_id, scan_id, type, to_status, at)'
            ' VALUES (?,?,?,?,?)', (fp, 's1', 'CREATED', 'OPEN', '2026-01-01'))
        conn.execute('PRAGMA user_version = 1')
    return fp


def test_migration_rekeys_findings_and_events(tmp_path):
    db = tmp_path / 'findings.db'
    fp = _seed_v1_db(db)

    store = FindingsStore(db)                       # opening triggers migration
    new_id = scoped_id('a.com', fp)

    # Version bumped; the row is now under the scoped id, not the bare fp.
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2
    assert store.get(fp) is None                    # old bare key gone
    row = store.get(new_id)
    assert row is not None
    assert row['status'] == 'IGNORED'               # user triage preserved
    assert row['title'] == 'No SPF record'

    # The event trail followed the row to the new id.
    assert [e['type'] for e in store.events(new_id)] == ['CREATED']
    assert store.events(fp) == []


def test_migration_is_idempotent(tmp_path):
    db = tmp_path / 'findings.db'
    fp = _seed_v1_db(db)
    new_id = scoped_id('a.com', fp)

    FindingsStore(db)                               # migrate once
    FindingsStore(db)                               # reopen — must not re-key

    store = FindingsStore(db)
    assert store.get(new_id) is not None
    assert store.summary('a.com')['total'] == 1     # no duplication / loss
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2


def test_fresh_db_initializes_at_v2_without_error(tmp_path):
    # A brand-new DB runs the (empty) migration and lands at v2.
    store = FindingsStore(tmp_path / 'fresh.db')
    assert store.projects() == []
    with sqlite3.connect(str(tmp_path / 'fresh.db')) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2
