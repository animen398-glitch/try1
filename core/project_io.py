"""core/project_io.py
Project export / import — move a whole project between machines (or share a demo)
as one portable ``.zip`` bundle.

A project lives in two places: its ``Projects/<slug>/`` tree (scans, report.json,
metadata.json, screenshots, …) AND its lifecycle slice in the global findings /
assets DBs (keyed by the project slug). This bundles both so an imported project
is self-sufficient — Findings, Assets, Criticality, Remediation and Timeline all
work after import, not just Overview/History.

Bundle layout (``format_version`` 1):

    manifest.json     # format/app version, slug, url, company, counts, exported_at
    findings.json     # FindingsStore.export_project(slug) — rows + events, verbatim
    assets.json       # AssetStore.export_project(slug)    — rows + events, verbatim
    audit_runs.json   # AuditRunStore.export_project(slug) — rows + events, verbatim
    missions.json     # MissionStore.export_project(slug)  — rows (no event log)
    engagements.json  # EngagementStore.export_project(slug) — rows (no event log)
    project/…         # the Projects/<slug>/ tree, paths relative to the project dir

Offline, stdlib only (``zipfile``). Reuses ProjectStore / FindingsStore /
AssetStore — no schema knowledge here. Import is hardened against zip-slip and,
via the stores' column whitelist, against SQL injection from a crafted bundle.
"""
from __future__ import annotations

import json
import logging
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Optional, Union

FORMAT_VERSION = 1
_MANIFEST = 'manifest.json'
_FINDINGS = 'findings.json'
_ASSETS = 'assets.json'
_AUDIT_RUNS = 'audit_runs.json'
_MISSIONS = 'missions.json'
_ENGAGEMENTS = 'engagements.json'
_TREE_PREFIX = 'project/'
logger = logging.getLogger(__name__)


def _validate_bundle_slug(slug: object) -> str:
    """Return a manifest slug only if it is a single safe project directory name."""
    if not isinstance(slug, str) or not slug:
        raise ValueError('unsafe project slug in bundle')
    posix = PurePosixPath(slug)
    win = PureWindowsPath(slug)
    if (posix.is_absolute() or win.is_absolute() or win.drive
            or len(posix.parts) != 1 or len(win.parts) != 1
            or posix.parts[0] in {'.', '..'}):
        raise ValueError(f'unsafe project slug in bundle: {slug!r}')
    return slug


def _read_manifest(zf: zipfile.ZipFile) -> Dict:
    manifest = json.loads(zf.read(_MANIFEST))
    if not isinstance(manifest, dict):
        raise ValueError('not a project bundle: manifest.json must be an object')
    fmt = manifest.get('format_version')
    if fmt != FORMAT_VERSION:
        raise ValueError(f'unsupported bundle format_version: {fmt!r}')
    manifest['slug'] = _validate_bundle_slug(manifest.get('slug'))
    return manifest


def _stores(findings_db, assets_db, audit_db=None, missions_db=None,
            engagements_db=None):
    from core.asset_store import AssetStore
    from core.audit_store import AuditRunStore
    from core.engagement_store import EngagementStore
    from core.findings_store import FindingsStore
    from core.mission_store import MissionStore
    return (FindingsStore(findings_db), AssetStore(assets_db),
            AuditRunStore(audit_db), MissionStore(missions_db),
            EngagementStore(engagements_db))


def export_project(base: Union[str, Path], slug: str, dest: Union[str, Path], *,
                   findings_db=None, assets_db=None, audit_db=None,
                   missions_db=None, engagements_db=None) -> Dict:
    """Bundle project ``slug`` (under workspace ``base``) into the ``dest`` zip.
    Raises ``KeyError`` if the project does not exist."""
    from core.config import APP_VERSION
    from core.project import ProjectStore
    from utils.sqlite_store import now_ts

    store = ProjectStore(base)
    proj = store.get(slug)
    if proj is None:
        raise KeyError(f'project not found: {slug}')

    (findings_store, assets_store, audit_store, mission_store,
     engagement_store) = _stores(
        findings_db, assets_db, audit_db, missions_db, engagements_db)
    findings = findings_store.export_project(slug)
    assets = assets_store.export_project(slug)
    audit_runs = audit_store.export_project(slug)
    missions = mission_store.export_project(slug)
    engagements = engagement_store.export_project(slug)
    meta = proj.load_metadata()

    manifest = {
        'format_version': FORMAT_VERSION,
        'app_version': APP_VERSION,
        'slug': slug,
        'url': meta.get('url'),
        'company': proj.get_company(),
        'exported_at': now_ts(),
        'counts': {
            'findings': len(findings['rows']),
            'finding_events': len(findings['events']),
            'assets': len(assets['rows']),
            'asset_events': len(assets['events']),
            'audit_runs': len(audit_runs['rows']),
            'audit_events': len(audit_runs['events']),
            'missions': len(missions['rows']),
            'engagements': len(engagements['rows']),
            'scans': len(meta.get('scans') or []),
        },
    }

    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(proj.root.rglob('*')):
            if p.is_file():
                zf.write(p, _TREE_PREFIX + p.relative_to(proj.root).as_posix())
        zf.writestr(_MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr(_FINDINGS, json.dumps(findings, ensure_ascii=False))
        zf.writestr(_ASSETS, json.dumps(assets, ensure_ascii=False))
        zf.writestr(_AUDIT_RUNS, json.dumps(audit_runs, ensure_ascii=False))
        zf.writestr(_MISSIONS, json.dumps(missions, ensure_ascii=False))
        zf.writestr(_ENGAGEMENTS, json.dumps(engagements, ensure_ascii=False))

    return {'path': str(dest), 'slug': slug, **manifest['counts']}


def _safe_extract(zf: zipfile.ZipFile, dest_dir: Path) -> int:
    """Extract the ``project/`` members under ``dest_dir`` with a zip-slip guard;
    returns the file count. Any member that would escape the target is rejected."""
    dest_root = dest_dir.resolve()
    n = 0
    for name in zf.namelist():
        if not name.startswith(_TREE_PREFIX) or name.endswith('/'):
            continue
        rel = name[len(_TREE_PREFIX):]
        if not rel:
            continue
        target = (dest_dir / rel).resolve()
        if not target.is_relative_to(dest_root):
            raise ValueError(f'unsafe path in bundle: {name}')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(name))
        n += 1
    return n


def import_project(src: Union[str, Path], base: Union[str, Path], *,
                   findings_db=None, assets_db=None, audit_db=None,
                   missions_db=None, engagements_db=None,
                   replace: bool = False) -> Dict:
    """Restore a bundle into workspace ``base``. If the project tree already
    exists it is skipped unless ``replace`` (which wipes the tree and the DB
    slice first). Returns a summary dict."""
    from core.project import ProjectStore

    src = Path(src)
    with zipfile.ZipFile(src) as zf:
        names = set(zf.namelist())
        if _MANIFEST not in names:
            raise ValueError('not a project bundle: manifest.json missing')
        manifest = _read_manifest(zf)
        slug = manifest['slug']

        store = ProjectStore(base)
        dest_dir = store.root / slug
        if dest_dir.exists():
            if not replace:
                return {'slug': slug, 'skipped': True, 'reason': 'project exists'}

        findings = json.loads(zf.read(_FINDINGS)) if _FINDINGS in names else {}
        assets = json.loads(zf.read(_ASSETS)) if _ASSETS in names else {}
        audit_runs = json.loads(zf.read(_AUDIT_RUNS)) if _AUDIT_RUNS in names else {}
        missions = json.loads(zf.read(_MISSIONS)) if _MISSIONS in names else {}
        engagements = (json.loads(zf.read(_ENGAGEMENTS))
                       if _ENGAGEMENTS in names else {})

        (findings_store, assets_store, audit_store, mission_store,
         engagement_store) = _stores(
            findings_db, assets_db, audit_db, missions_db, engagements_db)
        db_imports = (
            (findings_store, findings),
            (assets_store, assets),
            (audit_store, audit_runs),
            (mission_store, missions),
            (engagement_store, engagements),
        )
        for db_store, payload in db_imports:
            db_store.validate_project_import(slug, payload)
        previous_slices = [
            (db_store, db_store.export_project(slug))
            for db_store, _payload in db_imports
        ]

        store.root.mkdir(parents=True, exist_ok=True)
        # Stage everything inside a sibling temp dir on the same filesystem so the
        # final tree swap is an atomic rename. ``mkdtemp`` + a best-effort rmtree
        # (rather than ``TemporaryDirectory``) keeps a cleanup failure — e.g. a
        # locked file in the replaced tree on Windows — from masking the outcome.
        temp_root = Path(tempfile.mkdtemp(prefix=f'.import-{slug}-', dir=store.root))
        try:
            staged_tree = temp_root / 'project'
            staged_tree.mkdir()
            files = _safe_extract(zf, staged_tree)

            try:
                results = [
                    db_store.import_project(slug, payload, replace=replace)
                    for db_store, payload in db_imports
                ]

                previous_tree = temp_root / 'previous'
                if dest_dir.exists():
                    dest_dir.rename(previous_tree)
                try:
                    staged_tree.rename(dest_dir)
                except Exception:
                    # Tree swap failed: put the old tree back, but never let a
                    # restore failure shadow the original swap error.
                    if previous_tree.exists():
                        try:
                            previous_tree.rename(dest_dir)
                        except Exception:  # pragma: no cover - defensive
                            logger.exception(
                                'Failed to restore previous project tree '
                                'after a swap error')
                    raise
            except Exception as exc:
                rollback_errors = []
                for db_store, previous in reversed(previous_slices):
                    try:
                        db_store.import_project(slug, previous, replace=True)
                    except Exception as rollback_exc:  # pragma: no cover - defensive
                        rollback_errors.append(
                            f'{type(db_store).__name__}: {rollback_exc}')
                if rollback_errors:
                    exc.add_note('project import rollback errors: '
                                 + '; '.join(rollback_errors))
                    logger.exception('Project import rollback was incomplete')
                raise
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    fres, ares, au_res, mi_res, eng_res = results

    return {'slug': slug, 'skipped': False, 'files': files,
            'findings': fres['imported'], 'finding_events': fres['events'],
            'assets': ares['imported'], 'asset_events': ares['events'],
            'audit_runs': au_res['imported'], 'audit_events': au_res['events'],
            'missions': mi_res['imported'], 'engagements': eng_res['imported']}


def bundle_info(src: Union[str, Path]) -> Optional[Dict]:
    """Read a bundle's manifest without importing (for a confirm dialog/preview).
    Returns None if the file is not a valid project bundle."""
    try:
        with zipfile.ZipFile(Path(src)) as zf:
            return _read_manifest(zf)
    except (zipfile.BadZipFile, KeyError, ValueError, OSError, json.JSONDecodeError):
        return None
