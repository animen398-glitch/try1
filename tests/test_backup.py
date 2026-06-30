"""Full backup/restore (core/backup.py) — data root + workspace → one .zip.

SQLite stores are snapshotted via the online backup API; configs and the
workspace tree are copied verbatim. Restore is zip-slip guarded and skips
existing files unless replace=True. Offline, stdlib only.
"""

import sqlite3
import zipfile

import pytest

from core import backup


def _data_root(tmp_path):
    """A small data root: one SQLite DB + one config file."""
    root = tmp_path / 'data_root'
    (root / 'data').mkdir(parents=True)
    (root / 'configs').mkdir(parents=True)
    db = root / 'data' / 'findings.db'
    conn = sqlite3.connect(str(db))
    conn.execute('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)')
    conn.execute("INSERT INTO t (v) VALUES ('hello')")
    conn.commit()
    conn.close()
    (root / 'configs' / 'settings.json').write_text('{"k": 1}', encoding='utf-8')
    return root


def _workspace(tmp_path):
    ws = tmp_path / 'SiteAnalyzer'
    (ws / 'Projects' / 'x.com' / 'scans').mkdir(parents=True)
    (ws / 'Projects' / 'x.com' / 'metadata.json').write_text('{}', encoding='utf-8')
    return ws


def test_create_backup_captures_db_config_workspace(tmp_path):
    root, ws = _data_root(tmp_path), _workspace(tmp_path)
    dest = tmp_path / 'backup.zip'
    out = backup.create_backup(dest, data_root=root, workspace=ws)

    assert out['dbs'] == 1 and out['data_files'] >= 1 and out['workspace_files'] >= 1
    assert dest.exists() and out['bytes'] > 0
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
    assert 'manifest.json' in names
    assert 'data_root/data/findings.db' in names
    assert 'data_root/configs/settings.json' in names
    assert any(n.startswith('workspace/') for n in names)
    # WAL sidecars are never archived (online backup yields a standalone .db)
    assert not any(n.endswith(('-wal', '-shm')) for n in names)


def test_backup_info_reads_manifest(tmp_path):
    root = _data_root(tmp_path)
    dest = tmp_path / 'b.zip'
    backup.create_backup(dest, data_root=root, workspace=None)
    info = backup.backup_info(dest)
    assert info and info['format_version'] == backup.FORMAT_VERSION
    assert info['dbs'] == 1


def test_backup_info_rejects_non_backup(tmp_path):
    junk = tmp_path / 'junk.zip'
    with zipfile.ZipFile(junk, 'w') as zf:
        zf.writestr('hello.txt', 'not a backup')
    assert backup.backup_info(junk) is None


def test_restore_round_trip_into_clean_roots(tmp_path):
    root, ws = _data_root(tmp_path), _workspace(tmp_path)
    dest = tmp_path / 'backup.zip'
    backup.create_backup(dest, data_root=root, workspace=ws)

    new_root = tmp_path / 'restored_data'
    new_ws = tmp_path / 'restored_ws'
    out = backup.restore_backup(dest, data_root=new_root, workspace=new_ws)
    assert out['restored'] >= 3 and out['skipped'] == 0

    # the restored DB is a valid SQLite copy with the original row
    conn = sqlite3.connect(str(new_root / 'data' / 'findings.db'))
    assert conn.execute('SELECT v FROM t').fetchone()[0] == 'hello'
    conn.close()
    assert (new_root / 'configs' / 'settings.json').read_text(encoding='utf-8') == '{"k": 1}'
    assert (new_ws / 'Projects' / 'x.com' / 'metadata.json').exists()


def test_restore_skips_existing_unless_replace(tmp_path):
    root = _data_root(tmp_path)
    dest = tmp_path / 'backup.zip'
    backup.create_backup(dest, data_root=root, workspace=None)

    # restoring back onto the same (populated) root skips everything by default
    out = backup.restore_backup(dest, data_root=root, workspace=None)
    assert out['restored'] == 0 and out['skipped'] >= 2
    # with replace=True it overwrites
    out2 = backup.restore_backup(dest, data_root=root, workspace=None, replace=True)
    assert out2['restored'] >= 2 and out2['skipped'] == 0


def test_restore_rejects_non_backup(tmp_path):
    junk = tmp_path / 'junk.zip'
    with zipfile.ZipFile(junk, 'w') as zf:
        zf.writestr('x.txt', 'nope')
    with pytest.raises(ValueError, match='not a recognized backup'):
        backup.restore_backup(junk, data_root=tmp_path / 'd')


def test_restore_zip_slip_guard(tmp_path):
    # a malicious archive trying to escape the target dir is ignored, not written
    evil = tmp_path / 'evil.zip'
    with zipfile.ZipFile(evil, 'w') as zf:
        zf.writestr('manifest.json',
                    '{"format_version": %d}' % backup.FORMAT_VERSION)
        zf.writestr('data_root/../escape.txt', 'pwned')
    target = tmp_path / 'safe'
    out = backup.restore_backup(evil, data_root=target, workspace=None)
    assert not (tmp_path / 'escape.txt').exists()
    assert out['restored'] == 0


def test_workspace_inside_data_root_not_double_captured(tmp_path):
    root = _data_root(tmp_path)
    inside = root / 'workspaces'
    inside.mkdir()
    (inside / 'p.txt').write_text('x', encoding='utf-8')
    dest = tmp_path / 'b.zip'
    out = backup.create_backup(dest, data_root=root, workspace=inside)
    # nested workspace is covered by the data-root walk, not added again
    assert out['workspace_files'] == 0
    with zipfile.ZipFile(dest) as zf:
        assert 'data_root/workspaces/p.txt' in zf.namelist()
