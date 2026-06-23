"""core/asset_store.py
Asset Inventory persistence — the SQLite store for discovered assets.

The asset analogue of ``findings_store``: an asset lives across scans, not inside
one report. This keeps the ``assets`` table (one row per unique asset in a
project, keyed by ``scoped_id(project, asset_fingerprint)``) plus an
``asset_events`` trail (CREATED / SEEN / GONE / REAPPEARED). It is the persistent
*head* of the platform chain (Assets → Events → Findings → Risk → Timeline → …):
later stages link findings/risk/timeline to these stable asset rows.

Lifecycle is intentionally simpler than findings (assets aren't user-triaged):

  * **ACTIVE** — observed on the attack surface;
  * **GONE** — was active, absent from a scan whose producing phase actually ran
    (a skipped/failed phase must not look like "asset disappeared"); reappears →
    REAPPEARED → ACTIVE.

Design mirrors findings_store exactly (consistency, no new paradigm): built on
``SQLiteStore``, one DB (``data/assets.db`` via PathManager, frozen-aware) scoped
by the ``project`` column, idempotent ``CREATE TABLE IF NOT EXISTS`` schema with
``PRAGMA user_version``. ``attrs`` is JSON (version/provider/source/…).
"""

from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from core.config import ASSETS_DB
from core.finding_fingerprint import scoped_id
from utils.sqlite_store import SQLiteStore, now_ts as _now

STATUSES = ('ACTIVE', 'GONE')
ACTIVE_STATUS = 'ACTIVE'
GONE_STATUS = 'GONE'
EVENT_TYPES = ('CREATED', 'SEEN', 'GONE', 'REAPPEARED')
# Human-readable status labels — single source for the GUI tab and web console.
STATUS_LABELS = {'ACTIVE': 'Активен', 'GONE': 'Исчез'}


class AssetStore(SQLiteStore):
    """SQLite-backed persistence for assets + their event history."""

    JSON_FIELDS = ('attrs',)
    SCHEMA_VERSION = 1

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS assets (
        id            TEXT PRIMARY KEY,
        project       TEXT NOT NULL,
        type          TEXT NOT NULL,
        value         TEXT NOT NULL,
        label         TEXT,
        attrs         TEXT,
        status        TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at  TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS asset_events (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id  TEXT NOT NULL,
        scan_id   TEXT,
        type      TEXT NOT NULL,
        at        TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_assets_project ON assets(project);
    CREATE INDEX IF NOT EXISTS ix_assets_type ON assets(project, type);
    CREATE INDEX IF NOT EXISTS ix_asset_events_aid ON asset_events(asset_id);
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or ASSETS_DB)

    # ── internal ──────────────────────────────────────────────────────────────

    def _log_event(self, conn, asset_id: str, event_type: str, *,
                   scan_id: Optional[str] = None, at: Optional[str] = None) -> None:
        conn.execute(
            'INSERT INTO asset_events (asset_id, scan_id, type, at) '
            'VALUES (?,?,?,?)', (asset_id, scan_id, event_type, at or _now()))

    @staticmethod
    def _attrs_json(attrs) -> Optional[str]:
        if not attrs:
            return None
        import json
        return json.dumps(attrs, ensure_ascii=False, default=str)

    # ── writes ────────────────────────────────────────────────────────────────

    def upsert(self, project: str, asset: Dict, *, scan_id: Optional[str] = None,
               now: Optional[str] = None) -> Dict:
        """Insert a new asset (status ACTIVE, event CREATED) or refresh an
        existing one (bump last_seen, refresh label/attrs, event SEEN). Status is
        not changed here — a GONE asset reappearing is handled in :meth:`sync`.

        ``asset`` is an ``Asset.to_store()`` dict (``id`` = bare fingerprint). The
        stored row id is the project-scoped key. Returns ``{created, asset}``."""
        now = now or _now()
        aid = scoped_id(project, asset['id'])
        attrs = self._attrs_json(asset.get('attrs'))
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM assets WHERE id = ?',
                               (aid,)).fetchone()
            if row is None:
                conn.execute(
                    'INSERT INTO assets (id, project, type, value, label, attrs,'
                    ' status, first_seen_at, last_seen_at, updated_at)'
                    ' VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (aid, project, asset.get('type', ''), asset.get('value', ''),
                     asset.get('label'), attrs, ACTIVE_STATUS, now, now, now))
                self._log_event(conn, aid, 'CREATED', scan_id=scan_id, at=now)
                created = True
            else:
                conn.execute(
                    'UPDATE assets SET label = ?,'
                    ' attrs = COALESCE(?, attrs), last_seen_at = ?,'
                    ' updated_at = ? WHERE id = ?',
                    (asset.get('label', row['label']), attrs, now, now, aid))
                self._log_event(conn, aid, 'SEEN', scan_id=scan_id, at=now)
                created = False
            stored = conn.execute('SELECT * FROM assets WHERE id = ?',
                                  (aid,)).fetchone()
        return {'created': created, 'asset': self._row_to_dict(stored)}

    def set_status(self, asset_id: str, status: str, *, event_type: str,
                   scan_id: Optional[str] = None, now: Optional[str] = None) -> Dict:
        """Change an asset's status and log the transition (no-op if unchanged).

        Raises ``ValueError`` for an unknown status, ``KeyError`` for an unknown
        asset."""
        if status not in STATUSES:
            raise ValueError(f'unknown status: {status!r} (expected {STATUSES})')
        now = now or _now()
        with self._connect() as conn:
            row = conn.execute('SELECT status FROM assets WHERE id = ?',
                               (asset_id,)).fetchone()
            if row is None:
                raise KeyError(asset_id)
            if row['status'] != status:
                conn.execute('UPDATE assets SET status = ?, updated_at = ?'
                             ' WHERE id = ?', (status, now, asset_id))
                self._log_event(conn, asset_id, event_type, scan_id=scan_id, at=now)
            stored = conn.execute('SELECT * FROM assets WHERE id = ?',
                                  (asset_id,)).fetchone()
        return self._row_to_dict(stored)

    # ── lifecycle orchestration ───────────────────────────────────────────────

    @staticmethod
    def _gone_in_scope(row: Dict, in_scope: Optional[Callable[[str], bool]],
                       source_in_scope: Optional[Callable[[str], bool]]) -> bool:
        """May an absent ACTIVE asset be marked GONE this scan?

        Only when the phase that *produces this asset* actually ran (a skipped
        opt-in phase must not look like the asset disappeared). Prefer per-source
        gating — an asset records the ``source`` that derived it (recon /
        subdomains / certificate / ct / …), and a name seen only in the TLS
        certificate is not "gone" just because the active subdomain phase ran
        without it. Falls back to per-type gating for rows with no stored source
        (legacy rows / callers that pass only ``in_scope``)."""
        if source_in_scope is not None:
            src = (row.get('attrs') or {}).get('source')
            if src:
                return source_in_scope(src)
        if in_scope is not None:
            return in_scope(row['type'])
        return True

    def sync(self, project: str, scan_id: Optional[str], assets: List,
             *, in_scope: Optional[Callable[[str], bool]] = None,
             source_in_scope: Optional[Callable[[str], bool]] = None,
             now: Optional[str] = None) -> Dict:
        """Reconcile a scan's assets with the stored inventory.

        ``assets`` are ``Asset`` DTOs (from ``asset_adapter.derive_assets``).
        Rules mirror the findings lifecycle:
          * new fingerprint → CREATED / ACTIVE;
          * seen again → SEEN, EXCEPT a GONE asset reappearing → REAPPEARED →
            ACTIVE;
          * a stored ACTIVE asset NOT seen this scan → GONE, but only when its
            producing phase ran — gated per-source via ``source_in_scope(source)``
            when given, else per-type via ``in_scope(type)`` (see
            :meth:`_gone_in_scope`).

        Returns ``{new, recurring, reappeared, gone, summary}``.
        """
        now = now or _now()
        seen_ids, new, recurring, reappeared = set(), [], [], []
        for a in assets or []:
            res = self.upsert(project, a.to_store(), scan_id=scan_id, now=now)
            aid = res['asset']['id']
            seen_ids.add(aid)
            if res['created']:
                new.append(res['asset'])
            elif res['asset']['status'] == GONE_STATUS:
                reappeared.append(self.set_status(
                    aid, ACTIVE_STATUS, event_type='REAPPEARED',
                    scan_id=scan_id, now=now))
            else:
                recurring.append(res['asset'])

        gone = []
        for row in self.list_assets(project):
            if row['id'] in seen_ids or row['status'] != ACTIVE_STATUS:
                continue
            if not self._gone_in_scope(row, in_scope, source_in_scope):
                continue
            self.set_status(row['id'], GONE_STATUS, event_type='GONE',
                            scan_id=scan_id, now=now)
            gone.append(row)

        return {'new': new, 'recurring': recurring, 'reappeared': reappeared,
                'gone': gone, 'summary': self.summary(project)}

    # ── reads ─────────────────────────────────────────────────────────────────

    def get(self, asset_id: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM assets WHERE id = ?',
                               (asset_id,)).fetchone()
        return self._row_to_dict(row)

    def list_assets(self, project: Optional[str] = None,
                    type: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict]:
        """Assets, newest-updated first, optionally filtered by project/type/status."""
        clauses, params = [], []
        if project is not None:
            clauses.append('project = ?'); params.append(project)
        if type is not None:
            clauses.append('type = ?'); params.append(type)
        if status is not None:
            clauses.append('status = ?'); params.append(status)
        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT * FROM assets{where} ORDER BY updated_at DESC',
                params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def events(self, asset_id: str) -> List[Dict]:
        """Audit trail for one asset, oldest first."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM asset_events WHERE asset_id = ? ORDER BY id',
                (asset_id,)).fetchall()
        return [dict(r) for r in rows]

    def projects(self) -> List[Dict]:
        """Distinct projects that have assets, with total/active counts.

        The asset DB is the source of truth for the Assets view's project
        selector (mirrors ``FindingsStore.projects``), so a project keeps showing
        as long as it has stored assets. Newest-touched first."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT project, COUNT(*) total,'
                ' SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) active,'
                ' MAX(updated_at) updated_at'
                ' FROM assets GROUP BY project ORDER BY updated_at DESC',
                (ACTIVE_STATUS,)).fetchall()
        return [{'project': r['project'], 'total': r['total'],
                 'active': r['active'] or 0, 'updated_at': r['updated_at']}
                for r in rows]

    def project_events(self, project: str) -> List[Dict]:
        """All asset events for a project's assets, oldest first, enriched with
        each asset's type/value/label — the timeline's asset source (F2). Pure
        read; joins asset_events to assets by project."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT e.asset_id, e.scan_id, e.type, e.at,'
                ' a.type AS asset_type, a.value, a.label'
                ' FROM asset_events e JOIN assets a ON a.id = e.asset_id'
                ' WHERE a.project = ? ORDER BY e.id', (project,)).fetchall()
        return [dict(r) for r in rows]

    def summary(self, project: Optional[str] = None) -> Dict:
        """Counts by type + active/total for a project (Dashboard/inventory input)."""
        where, params = '', []
        if project is not None:
            where = ' WHERE project = ?'; params.append(project)
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT type, status, COUNT(*) c FROM assets{where}'
                f' GROUP BY type, status', params).fetchall()
        by_type: Dict[str, int] = {}
        total = active = 0
        for r in rows:
            by_type[r['type']] = by_type.get(r['type'], 0) + r['c']
            total += r['c']
            if r['status'] == ACTIVE_STATUS:
                active += r['c']
        return {'total': total, 'active': active, 'by_type': by_type}
