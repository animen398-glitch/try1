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
    project/…         # the Projects/<slug>/ tree, paths relative to the project dir

Offline, stdlib only (``zipfile``). Reuses ProjectStore / FindingsStore /
AssetStore — no schema knowledge here. Import is hardened against zip-slip and,
via the stores' column whitelist, against SQL injection from a crafted bundle.
"""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Optional, Union

FORMAT_VERSION = 1
_MANIFEST = 'manifest.json'
_FINDINGS = 'findings.json'
_ASSETS = 'assets.json'
_TREE_PREFIX = 'project/'


def _stores(findings_db, assets_db):
    from core.asset_store import AssetStore
    from core.findings_store import FindingsStore
    return FindingsStore(findings_db), AssetStore(assets_db)


def export_project(base: Union[str, Path], slug: str, dest: Union[str, Path], *,
                   findings_db=None, assets_db=None) -> Dict:
    """Bundle project ``slug`` (under workspace ``base``) into the ``dest`` zip.
    Raises ``KeyError`` if the project does not exist."""
    from core.config import APP_VERSION
    from core.project import ProjectStore
    from utils.sqlite_store import now_ts

    store = ProjectStore(base)
    proj = store.get(slug)
    if proj is None:
        raise KeyError(f'project not found: {slug}')

    findings_store, assets_store = _stores(findings_db, assets_db)
    findings = findings_store.export_project(slug)
    assets = assets_store.export_project(slug)
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
                   findings_db=None, assets_db=None, replace: bool = False) -> Dict:
    """Restore a bundle into workspace ``base``. If the project tree already
    exists it is skipped unless ``replace`` (which wipes the tree and the DB
    slice first). Returns a summary dict."""
    from core.project import ProjectStore

    src = Path(src)
    with zipfile.ZipFile(src) as zf:
        names = set(zf.namelist())
        if _MANIFEST not in names:
            raise ValueError('not a project bundle: manifest.json missing')
        manifest = json.loads(zf.read(_MANIFEST))
        fmt = manifest.get('format_version')
        if fmt != FORMAT_VERSION:
            raise ValueError(f'unsupported bundle format_version: {fmt!r}')
        slug = manifest['slug']

        store = ProjectStore(base)
        dest_dir = store.root / slug
        if dest_dir.exists():
            if not replace:
                return {'slug': slug, 'skipped': True, 'reason': 'project exists'}
            shutil.rmtree(dest_dir)

        files = _safe_extract(zf, dest_dir)
        findings = json.loads(zf.read(_FINDINGS)) if _FINDINGS in names else {}
        assets = json.loads(zf.read(_ASSETS)) if _ASSETS in names else {}

    findings_store, assets_store = _stores(findings_db, assets_db)
    fres = findings_store.import_project(slug, findings, replace=replace)
    ares = assets_store.import_project(slug, assets, replace=replace)

    return {'slug': slug, 'skipped': False, 'files': files,
            'findings': fres['imported'], 'finding_events': fres['events'],
            'assets': ares['imported'], 'asset_events': ares['events']}


def bundle_info(src: Union[str, Path]) -> Optional[Dict]:
    """Read a bundle's manifest without importing (for a confirm dialog/preview).
    Returns None if the file is not a valid project bundle."""
    try:
        with zipfile.ZipFile(Path(src)) as zf:
            return json.loads(zf.read(_MANIFEST))
    except (zipfile.BadZipFile, KeyError, ValueError, OSError):
        return None
