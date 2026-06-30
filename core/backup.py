"""core/backup.py
Full backup — a timestamped ``.zip`` snapshot of the whole data root plus the
project workspace, restorable offline.

The app's state lives in two places: the writable **data root** (SQLite stores
under ``data/``, config JSON under ``configs/``) and the **workspace** (the
``Projects/<slug>/`` trees, under the settings ``output_dir`` — usually outside
the data root). :func:`create_backup` captures both into one archive:

* every ``*.db`` is snapshotted with SQLite's **online backup** API — a
  consistent copy even while the app reads it (the stores use WAL), with no
  ``-wal``/``-shm`` sidecars in the archive;
* every other data-root file (config JSON, companies registry, …) is copied
  verbatim;
* the workspace tree is copied verbatim under ``workspace/``.

:func:`restore_backup` extracts an archive back onto target roots, zip-slip
guarded; existing files are skipped unless ``replace=True`` (a restore never
silently clobbers live data). Stdlib only (``zipfile`` / ``sqlite3``).
"""

from __future__ import annotations

import json
import sqlite3
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

FORMAT_VERSION = 1
MANIFEST_NAME = 'manifest.json'
_DATA_PREFIX = 'data_root/'
_WORKSPACE_PREFIX = 'workspace/'
# Never archived: WAL sidecars (the online backup already produces a consistent
# standalone .db) and corruption quarantines.
_SKIP_SUFFIXES = ('-wal', '-shm')


def _is_skippable(path: Path) -> bool:
    name = path.name
    return (name.endswith(_SKIP_SUFFIXES) or '.corrupt-' in name)


def _iter_files(root: Path):
    for p in sorted(root.rglob('*')):
        if p.is_file() and not _is_skippable(p):
            yield p


def _online_backup_bytes(db_path: Path, tmp_dir: Path) -> bytes:
    """A consistent snapshot of a SQLite DB via the online backup API, returned
    as bytes. Falls back to the raw file bytes if the online backup fails (e.g.
    the file is not actually a SQLite DB)."""
    dst = tmp_dir / (db_path.name + '.snap')
    src = sqlite3.connect(str(db_path))
    try:
        out = sqlite3.connect(str(dst))
        try:
            src.backup(out)
        finally:
            out.close()
    finally:
        src.close()
    return dst.read_bytes()


def _resolve_roots(data_root, workspace):
    if data_root is None:
        from core.paths import get_path_manager
        data_root = get_path_manager().data_root
    if workspace is None:
        from core.config import load_settings
        workspace = load_settings().get('output_dir') or ''
    return Path(data_root), (Path(workspace) if workspace else None)


def create_backup(dest_zip: Union[str, Path], *,
                  data_root: Optional[Union[str, Path]] = None,
                  workspace: Optional[Union[str, Path]] = None) -> Dict:
    """Snapshot the data root + workspace into ``dest_zip`` (created/overwritten).

    Returns ``{'path', 'dbs', 'data_files', 'workspace_files', 'bytes',
    'warnings'}``. SQLite DBs use the online backup API; everything else is copied
    verbatim. The workspace is skipped when it is missing or already inside the
    data root (so it is not captured twice)."""
    import tempfile

    data_root, workspace = _resolve_roots(data_root, workspace)
    dest = Path(dest_zip)
    dest.parent.mkdir(parents=True, exist_ok=True)

    dbs = data_files = workspace_files = 0
    warnings: List[str] = []

    # Skip a workspace nested inside the data root — it is already covered.
    ws_separate = False
    if workspace and workspace.exists():
        try:
            workspace.resolve().relative_to(data_root.resolve())
        except ValueError:
            ws_separate = True

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zf:
            if data_root.exists():
                for f in _iter_files(data_root):
                    rel = f.relative_to(data_root).as_posix()
                    arc = _DATA_PREFIX + rel
                    if f.suffix == '.db':
                        try:
                            zf.writestr(arc, _online_backup_bytes(f, tmp))
                            dbs += 1
                            continue
                        except Exception as e:  # noqa: BLE001 — fall back to raw copy
                            warnings.append(f'db {rel}: online backup failed ({e}); '
                                            'copied raw')
                    zf.writestr(arc, f.read_bytes())
                    data_files += 1
            if ws_separate:
                for f in _iter_files(workspace):
                    rel = f.relative_to(workspace).as_posix()
                    zf.writestr(_WORKSPACE_PREFIX + rel, f.read_bytes())
                    workspace_files += 1
            manifest = {
                'format_version': FORMAT_VERSION,
                'created_at': datetime.now().isoformat(timespec='seconds'),
                'data_root': data_root.name,
                'workspace': workspace.name if (ws_separate and workspace) else None,
                'dbs': dbs, 'data_files': data_files,
                'workspace_files': workspace_files,
                'warnings': warnings,
            }
            zf.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False,
                                                  indent=2))

    return {'path': str(dest), 'dbs': dbs, 'data_files': data_files,
            'workspace_files': workspace_files, 'bytes': dest.stat().st_size,
            'warnings': warnings}


def backup_info(src: Union[str, Path]) -> Optional[Dict]:
    """The manifest of a backup archive, or ``None`` if it is not one."""
    try:
        with zipfile.ZipFile(Path(src)) as zf:
            with zf.open(MANIFEST_NAME) as fh:
                manifest = json.load(fh)
        return manifest if manifest.get('format_version') == FORMAT_VERSION else None
    except Exception:  # noqa: BLE001
        return None


def _safe_target(dest_dir: Path, rel: str) -> Optional[Path]:
    """Resolve ``rel`` under ``dest_dir`` with a zip-slip guard (None if it would
    escape the directory)."""
    target = (dest_dir / rel).resolve()
    try:
        target.relative_to(dest_dir.resolve())
    except ValueError:
        return None
    return target


def restore_backup(src: Union[str, Path], *,
                   data_root: Optional[Union[str, Path]] = None,
                   workspace: Optional[Union[str, Path]] = None,
                   replace: bool = False) -> Dict:
    """Extract a backup archive back onto the target roots (zip-slip guarded).

    Existing files are **skipped** unless ``replace=True`` — a restore never
    silently clobbers live data. Returns ``{'restored', 'skipped', 'data_root',
    'workspace'}``."""
    info = backup_info(src)
    if info is None:
        raise ValueError('not a recognized backup archive')
    data_root, workspace = _resolve_roots(data_root, workspace)

    restored = skipped = 0
    with zipfile.ZipFile(Path(src)) as zf:
        for name in zf.namelist():
            if name.endswith('/') or name == MANIFEST_NAME:
                continue
            if name.startswith(_DATA_PREFIX):
                target = _safe_target(data_root, name[len(_DATA_PREFIX):])
            elif name.startswith(_WORKSPACE_PREFIX):
                if workspace is None:
                    continue
                target = _safe_target(workspace, name[len(_WORKSPACE_PREFIX):])
            else:
                continue
            if target is None:
                continue
            if target.exists() and not replace:
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(name) as fh:
                target.write_bytes(fh.read())
            restored += 1

    return {'restored': restored, 'skipped': skipped,
            'data_root': str(data_root),
            'workspace': str(workspace) if workspace else None}
