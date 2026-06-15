"""core/findings_store.py
Findings persistence — the SQLite store for Findings Management (roadmap F1,
task T1.2).

A finding lives across scans now, not inside one report: this store keeps the
`findings` table (one row per unique problem in a project, keyed by the stable
:func:`core.finding_fingerprint.fingerprint`) plus a `finding_events` audit
trail (CREATED / SEEN / STATUS_CHANGED / REOPENED / RESOLVED_AUTO). It replaces
the earlier JSON `findings.json` triage (#14): one store, no duplication.

Scope of T1.2 = the persistence layer only — schema, idempotent migration, and
the CRUD/event primitives. The lifecycle *orchestration* (turning a scan's
findings into upserts + auto-FIXED for the absent ones, with phase-success
guards and IGNORED/FALSE_POSITIVE stickiness) is :meth:`sync`, wired into
CollectionRunner in T1.4; the per-scanner → Finding adapters are T1.3.

Design:
  * One DB (``data/findings.db`` via PathManager, frozen-aware) scoped by the
    ``project`` column — mirrors operations.db/registry.db and lets the
    Dashboard / web console query across projects.
  * Built on ``utils.sqlite_store.SQLiteStore`` — schema is ``CREATE TABLE IF
    NOT EXISTS`` so init is idempotent and never disturbs an existing DB; a
    ``PRAGMA user_version`` carries the schema version for future migrations.
  * ``evidence`` is stored as JSON (masked — never raw secret values, same rule
    as the fingerprint discriminator).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from core.config import FINDINGS_DB
from core.finding_fingerprint import scoped_id
from utils.sqlite_store import SQLiteStore

# Finding lifecycle states. OPEN is the implicit state of a freshly created
# finding; FIXED/IGNORED/FALSE_POSITIVE are inactive (excluded from risk);
# IGNORED/FALSE_POSITIVE are additionally *suppressed* — sticky, never
# auto-reopened or alerted (anti-noise, the TruffleHog/DefectDojo idea).
STATUSES = ('OPEN', 'IN_PROGRESS', 'FIXED', 'IGNORED', 'FALSE_POSITIVE')
DEFAULT_STATUS = 'OPEN'
# Canonical severity scale, highest first (mirrors findings_adapter._SEVERITY
# targets) — used to order the GUI severity filter.
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'info')
INACTIVE_STATUSES = frozenset({'FIXED', 'IGNORED', 'FALSE_POSITIVE'})
SUPPRESSED_STATUSES = frozenset({'IGNORED', 'FALSE_POSITIVE'})

EVENT_TYPES = ('CREATED', 'SEEN', 'STATUS_CHANGED', 'REOPENED', 'RESOLVED_AUTO')

# Display labels (RU) for statuses — single source shared by the GUI Findings
# tab and the report card, so the two never drift.
STATUS_LABELS = {
    'OPEN': 'Открыто', 'IN_PROGRESS': 'В работе', 'FIXED': 'Исправлено',
    'IGNORED': 'Игнор', 'FALSE_POSITIVE': 'Ложное',
}

# v2: findings are keyed by their project-scoped id (scoped_id(project,
# fingerprint)) instead of the bare, project-agnostic fingerprint — so two
# projects no longer collide on a location-less finding (DNS / host-level).
SCHEMA_VERSION = 2


def _now() -> str:
    return datetime.now().isoformat(timespec='seconds')


class FindingsStore(SQLiteStore):
    """SQLite-backed persistence for findings + their event history."""

    JSON_FIELDS = ('evidence',)

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id            TEXT PRIMARY KEY,
        project       TEXT NOT NULL,
        category      TEXT NOT NULL,
        rule_id       TEXT,
        title         TEXT NOT NULL,
        severity      TEXT NOT NULL,
        status        TEXT NOT NULL,
        evidence      TEXT,
        first_seen_at TEXT NOT NULL,
        last_seen_at  TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        status_source TEXT
    );
    CREATE TABLE IF NOT EXISTS finding_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id  TEXT NOT NULL,
        scan_id     TEXT,
        type        TEXT NOT NULL,
        from_status TEXT,
        to_status   TEXT,
        note        TEXT,
        at          TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_findings_project ON findings(project);
    CREATE INDEX IF NOT EXISTS ix_finding_events_fid ON finding_events(finding_id);
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        super().__init__(db_path or FINDINGS_DB)

    def _init_schema(self) -> None:
        super()._init_schema()  # CREATE TABLE IF NOT EXISTS (idempotent)
        with self._connect() as conn:
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            if version < 2:
                self._migrate_to_v2(conn)
            conn.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')

    @staticmethod
    def _migrate_to_v2(conn) -> None:
        """Re-key v1 rows to their project-scoped id (the B fix). A v1 DB keyed
        findings by the bare fingerprint, so a location-less finding could be
        stored only once across projects; re-hashing each row's id with its
        project makes them distinct. No-op on an empty/new DB; idempotent via
        ``user_version`` (only runs while it is < 2)."""
        rows = conn.execute('SELECT id, project FROM findings').fetchall()
        for r in rows:
            old, project = r['id'], r['project']
            new = scoped_id(project, old)
            if new != old:
                # finding_events.finding_id mirrors the row id — move it too.
                conn.execute('UPDATE finding_events SET finding_id = ? '
                             'WHERE finding_id = ?', (new, old))
                conn.execute('UPDATE findings SET id = ? WHERE id = ?',
                             (new, old))

    # ── internal helpers ──────────────────────────────────────────────────────

    def _log_event(self, conn, finding_id: str, event_type: str, *,
                   scan_id: Optional[str] = None, from_status: Optional[str] = None,
                   to_status: Optional[str] = None, note: Optional[str] = None,
                   at: Optional[str] = None) -> None:
        conn.execute(
            'INSERT INTO finding_events '
            '(finding_id, scan_id, type, from_status, to_status, note, at) '
            'VALUES (?,?,?,?,?,?,?)',
            (finding_id, scan_id, event_type, from_status, to_status, note,
             at or _now()))

    @staticmethod
    def _evidence_json(evidence) -> Optional[str]:
        if evidence in (None, ''):
            return None
        return json.dumps(evidence, ensure_ascii=False, default=str)

    # ── writes ────────────────────────────────────────────────────────────────

    def upsert(self, project: str, finding: Dict, *, scan_id: Optional[str] = None,
               now: Optional[str] = None) -> Dict:
        """Insert a new finding (status OPEN, event CREATED) or refresh an
        existing one (bump last_seen, event SEEN) — status is never touched here.

        ``finding`` is a normalized DTO dict: ``id`` (= the bare, project-agnostic
        fingerprint), ``category``, ``title``, ``severity``, optional ``rule_id`` /
        ``evidence``. The stored row id is the *project-scoped* key derived from
        it, so the same fingerprint in two projects yields two rows. Returns
        ``{'created': bool, 'finding': <row>}`` (the row carries the scoped id)."""
        now = now or _now()
        fid = scoped_id(project, finding['id'])
        evidence = self._evidence_json(finding.get('evidence'))
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM findings WHERE id = ?',
                               (fid,)).fetchone()
            if row is None:
                conn.execute(
                    'INSERT INTO findings (id, project, category, rule_id, title,'
                    ' severity, status, evidence, first_seen_at, last_seen_at,'
                    ' updated_at, status_source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                    (fid, project, finding.get('category', ''),
                     finding.get('rule_id'), finding.get('title', ''),
                     finding.get('severity', ''), DEFAULT_STATUS, evidence,
                     now, now, now, 'auto'))
                self._log_event(conn, fid, 'CREATED', scan_id=scan_id,
                                to_status=DEFAULT_STATUS, at=now)
                created = True
            else:
                # Refresh display fields to the latest wording; status untouched.
                conn.execute(
                    'UPDATE findings SET title = ?, severity = ?, category = ?,'
                    ' rule_id = ?, evidence = COALESCE(?, evidence),'
                    ' last_seen_at = ?, updated_at = ? WHERE id = ?',
                    (finding.get('title', row['title']),
                     finding.get('severity', row['severity']),
                     finding.get('category', row['category']),
                     finding.get('rule_id', row['rule_id']), evidence,
                     now, now, fid))
                self._log_event(conn, fid, 'SEEN', scan_id=scan_id, at=now)
                created = False
            stored = conn.execute('SELECT * FROM findings WHERE id = ?',
                                  (fid,)).fetchone()
        return {'created': created, 'finding': self._row_to_dict(stored)}

    def set_status(self, finding_id: str, status: str, *,
                   note: Optional[str] = None, source: str = 'user',
                   event_type: str = 'STATUS_CHANGED',
                   scan_id: Optional[str] = None, now: Optional[str] = None) -> Dict:
        """Change a finding's status and log the transition. No-ops (no event) if
        the status is unchanged. ``event_type`` lets the lifecycle layer (T1.4)
        record REOPENED / RESOLVED_AUTO instead of the default STATUS_CHANGED.

        Raises ``ValueError`` for an unknown status, ``KeyError`` for an unknown
        finding."""
        if status not in STATUSES:
            raise ValueError(f'unknown status: {status!r} (expected {STATUSES})')
        now = now or _now()
        with self._connect() as conn:
            row = conn.execute('SELECT status FROM findings WHERE id = ?',
                               (finding_id,)).fetchone()
            if row is None:
                raise KeyError(finding_id)
            from_status = row['status']
            if from_status != status:
                conn.execute(
                    'UPDATE findings SET status = ?, status_source = ?,'
                    ' updated_at = ? WHERE id = ?',
                    (status, source, now, finding_id))
                self._log_event(conn, finding_id, event_type, scan_id=scan_id,
                                from_status=from_status, to_status=status,
                                note=note, at=now)
            stored = conn.execute('SELECT * FROM findings WHERE id = ?',
                                  (finding_id,)).fetchone()
        return self._row_to_dict(stored)

    # ── lifecycle orchestration ───────────────────────────────────────────────

    def sync(self, project: str, scan_id: Optional[str], findings: List[Dict], *,
             in_scope=None, now: Optional[str] = None) -> Dict:
        """Reconcile a scan's findings with the stored state (the F1 lifecycle).

        ``findings`` are raw scanner dicts; they're normalized to Finding DTOs
        here. Rules:
          * new fingerprint → CREATED / OPEN;
          * seen again → SEEN (status untouched), EXCEPT a previously FIXED one
            re-appears → REOPENED → OPEN;
          * a stored OPEN/IN_PROGRESS finding NOT seen this scan → RESOLVED_AUTO
            → FIXED, but only when ``in_scope(source)`` is true (the source phase
            actually ran — a skipped/failed phase must not look like "fixed");
          * IGNORED / FALSE_POSITIVE are sticky: never auto-reopened, never
            auto-fixed (they aren't OPEN/IN_PROGRESS, so both rules skip them).

        ``in_scope(source) -> bool`` (default: everything in scope) gates the
        auto-FIX so the caller can scope it to phases that succeeded. Returns a
        diff ``{new, recurring, reopened, resolved, summary}``.
        """
        from core.findings_adapter import normalize
        now = now or _now()
        seen_ids = set()
        new, recurring, reopened = [], [], []
        for f in normalize(findings):
            res = self.upsert(project, f.to_store(), scan_id=scan_id, now=now)
            # The stored row is keyed by the project-scoped id; track and act on
            # that, not the bare fingerprint, so "seen this scan" and REOPEN match.
            sid = res['finding']['id']
            seen_ids.add(sid)
            if res['created']:
                new.append(res['finding'])
            elif res['finding']['status'] == 'FIXED':
                reopened.append(self.set_status(
                    sid, 'OPEN', source='auto', event_type='REOPENED',
                    scan_id=scan_id, now=now))
            else:
                recurring.append(res['finding'])

        resolved = []
        for row in self.list_findings(project):
            if row['id'] in seen_ids or row['status'] not in ('OPEN', 'IN_PROGRESS'):
                continue
            evidence = row.get('evidence')
            source = evidence.get('source', '') if isinstance(evidence, dict) else ''
            if in_scope is not None and not in_scope(source):
                continue
            self.set_status(row['id'], 'FIXED', source='auto',
                            event_type='RESOLVED_AUTO', scan_id=scan_id, now=now)
            resolved.append(row)

        return {'new': new, 'recurring': recurring, 'reopened': reopened,
                'resolved': resolved, 'summary': self.summary(project)}

    # ── reads ─────────────────────────────────────────────────────────────────

    def get(self, finding_id: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM findings WHERE id = ?',
                               (finding_id,)).fetchone()
        return self._row_to_dict(row)

    def list_findings(self, project: Optional[str] = None,
                      status: Optional[str] = None,
                      severity: Optional[str] = None) -> List[Dict]:
        """Findings, newest-updated first, optionally filtered."""
        clauses, params = [], []
        if project is not None:
            clauses.append('project = ?'); params.append(project)
        if status is not None:
            clauses.append('status = ?'); params.append(status)
        if severity is not None:
            clauses.append('severity = ?'); params.append(severity)
        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT * FROM findings{where} ORDER BY updated_at DESC',
                params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def active_findings(self, project: Optional[str] = None) -> List[Dict]:
        """Findings that still count toward risk (status not in INACTIVE)."""
        placeholders = ','.join('?' * len(INACTIVE_STATUSES))
        params: List = list(INACTIVE_STATUSES)
        proj = ''
        if project is not None:
            proj = ' AND project = ?'; params.append(project)
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT * FROM findings WHERE status NOT IN ({placeholders})'
                f'{proj} ORDER BY updated_at DESC', params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def events(self, finding_id: str) -> List[Dict]:
        """Audit trail for one finding, oldest first."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM finding_events WHERE finding_id = ? ORDER BY id',
                (finding_id,)).fetchall()
        return [dict(r) for r in rows]

    def projects(self) -> List[Dict]:
        """Distinct projects that have findings, with total/active counts.

        The findings DB is the source of truth for the Findings view's project
        selector (independent of the Projects/ tree), so a project keeps showing
        as long as it has stored findings. Newest-touched first."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT project,'
                ' COUNT(*) total,'
                ' SUM(CASE WHEN status IN (?,?,?) THEN 0 ELSE 1 END) active,'
                ' MAX(updated_at) updated_at'
                ' FROM findings GROUP BY project ORDER BY updated_at DESC',
                tuple(INACTIVE_STATUSES)).fetchall()
        return [{'project': r['project'], 'total': r['total'],
                 'active': r['active'] or 0} for r in rows]

    def reopen_dates(self, project: Optional[str] = None) -> Dict[str, str]:
        """``finding_id → timestamp of its most recent REOPENED event``.

        The SLA clock restarts when a fixed finding reappears, so the remediation
        window must be measured from the latest reopen, not the original
        discovery (see ``findings_sla._reference``). Pure read; only findings
        that ever reopened appear in the map (the common case — never reopened —
        is simply absent, and SLA falls back to ``first_seen_at``)."""
        if project is not None:
            sql = ("SELECT e.finding_id fid, MAX(e.at) at FROM finding_events e"
                   " JOIN findings f ON f.id = e.finding_id"
                   " WHERE e.type = 'REOPENED' AND f.project = ?"
                   " GROUP BY e.finding_id")
            params: tuple = (project,)
        else:
            sql = ("SELECT finding_id fid, MAX(at) at FROM finding_events"
                   " WHERE type = 'REOPENED' GROUP BY finding_id")
            params = ()
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return {r['fid']: r['at'] for r in rows}

    def project_events(self, project: str) -> List[Dict]:
        """All finding events for a project's findings, oldest first, enriched
        with each finding's title/severity/category — the timeline's findings
        source (F2). Pure read; joins finding_events to findings by project."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT e.finding_id, e.scan_id, e.type, e.from_status,'
                ' e.to_status, e.note, e.at, f.title, f.severity, f.category'
                ' FROM finding_events e JOIN findings f ON f.id = e.finding_id'
                ' WHERE f.project = ? ORDER BY e.id', (project,)).fetchall()
        return [dict(r) for r in rows]

    def summary(self, project: Optional[str] = None) -> Dict:
        """Counts by status + active/total for a project (Dashboard/risk input)."""
        where, params = '', []
        if project is not None:
            where = ' WHERE project = ?'; params.append(project)
        by_status = {s: 0 for s in STATUSES}
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT status, COUNT(*) c FROM findings{where} GROUP BY status',
                params).fetchall()
        for r in rows:
            by_status[r['status']] = r['c']
        total = sum(by_status.values())
        active = sum(n for s, n in by_status.items() if s not in INACTIVE_STATUSES)
        return {'total': total, 'active': active, 'by_status': by_status}
