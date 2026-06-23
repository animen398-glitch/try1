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
from pathlib import Path
from typing import Dict, List, Optional, Union

from core.config import FINDINGS_DB
from core.finding_fingerprint import scoped_id
from core.severity import SEVERITY_ORDER  # noqa: F401 — re-exported for the GUI Findings tab
from utils.sqlite_store import SQLiteStore, now_ts as _now

# Finding lifecycle states. OPEN is the implicit state of a freshly created
# finding; FIXED/IGNORED/FALSE_POSITIVE are inactive (excluded from risk);
# IGNORED/FALSE_POSITIVE are additionally *suppressed* — sticky, never
# auto-reopened or alerted (anti-noise, the TruffleHog/DefectDojo idea).
STATUSES = ('OPEN', 'IN_PROGRESS', 'FIXED', 'IGNORED', 'FALSE_POSITIVE')
DEFAULT_STATUS = 'OPEN'
# SEVERITY_ORDER (canonical scale, highest first) comes from core.severity and is
# re-exported here — the GUI Findings tab imports it from this module to order its
# severity filter.
INACTIVE_STATUSES = frozenset({'FIXED', 'IGNORED', 'FALSE_POSITIVE'})
SUPPRESSED_STATUSES = frozenset({'IGNORED', 'FALSE_POSITIVE'})

EVENT_TYPES = ('CREATED', 'SEEN', 'STATUS_CHANGED', 'REOPENED', 'RESOLVED_AUTO',
               'SLA_BREACH', 'SECRET_ALERTED', 'FINDING_ALERTED', 'ISSUE_CREATED',
               'REMEDIATION')

# Display labels (RU) for statuses — single source shared by the GUI Findings
# tab and the report card, so the two never drift.
STATUS_LABELS = {
    'OPEN': 'Открыто', 'IN_PROGRESS': 'В работе', 'FIXED': 'Исправлено',
    'IGNORED': 'Игнор', 'FALSE_POSITIVE': 'Ложное',
}


class FindingsStore(SQLiteStore):
    """SQLite-backed persistence for findings + their event history."""

    JSON_FIELDS = ('evidence',)
    # Project-scoped export/import slice (core.project_io): findings + their events.
    PROJECT_EXPORT = ('findings', 'finding_events', 'finding_id')
    # v2: findings are keyed by their project-scoped id (scoped_id(project,
    # fingerprint)) instead of the bare, project-agnostic fingerprint — so two
    # projects no longer collide on a location-less finding (DNS / host-level).
    SCHEMA_VERSION = 2

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

    # Declarative migration map consumed by SQLiteStore._apply_migrations:
    # {target_version: fn(conn)}. Applied once when the on-disk version is below
    # the target (the ``user_version`` guard, not the op itself, gives
    # idempotency — re-keying twice would double-scope).
    MIGRATIONS = {2: _migrate_to_v2.__func__}

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

    def _record_oneshot(self, finding_ids: List[str], event_type: str, *,
                        scan_id: Optional[str] = None,
                        now: Optional[str] = None) -> List[str]:
        """Stamp each finding with a one-shot ``event_type`` marker and return the
        newly-marked ids (in input order). Shared guard for alert channels whose
        trigger has no Scan Diff representation (SLA breach, audit-only secret) and
        so need a persisted "already fired this episode" flag without a second
        table. A marker is treated as *already fired* only when it is newer than the
        finding's latest ``REOPENED`` event, so a fixed finding that reappears
        (which restarts the SLA clock / re-exposes a secret) is eligible to fire
        again on its next occurrence."""
        ids = list(dict.fromkeys(str(i) for i in (finding_ids or []) if i))
        if not ids:
            return []
        now = now or _now()
        placeholders = ','.join('?' * len(ids))
        new: List[str] = []
        with self._connect() as conn:
            def latest(et: str) -> Dict[str, str]:
                rows = conn.execute(
                    f'SELECT finding_id fid, MAX(at) at FROM finding_events'
                    f' WHERE type = ? AND finding_id IN ({placeholders})'
                    f' GROUP BY finding_id', (et, *ids)).fetchall()
                return {r['fid']: r['at'] for r in rows}

            marker_at, reopen_at = latest(event_type), latest('REOPENED')
            for fid in ids:
                marked = marker_at.get(fid)
                reopened = reopen_at.get(fid)
                already = marked is not None and (reopened is None
                                                  or marked > reopened)
                if already:
                    continue
                self._log_event(conn, fid, event_type, scan_id=scan_id, at=now)
                new.append(fid)
        return new

    def record_sla_breaches(self, project: str, breached_ids: List[str], *,
                            scan_id: Optional[str] = None,
                            now: Optional[str] = None) -> List[str]:
        """Mark findings as SLA-breached *once* and return the newly-marked ids.

        SLA breach is time-, not scan-triggered (a finding slips past its deadline
        by the passage of time), so the alert path needs a one-shot guard to fire
        per breach exactly once across monitor runs — without a second table (see
        ``_record_oneshot`` for the episode-aware guard semantics).

        ``breached_ids`` are the project-scoped stored ids of currently-breached
        findings (from ``active_findings``). Returns the subset that was not yet
        alerted for its current open episode (and is now marked), in input order.
        """
        return self._record_oneshot(breached_ids, 'SLA_BREACH',
                                     scan_id=scan_id, now=now)

    def record_secret_alerts(self, project: str, finding_ids: List[str], *,
                             scan_id: Optional[str] = None,
                             now: Optional[str] = None) -> List[str]:
        """Mark audit-only secret findings as alerted *once* and return the
        newly-marked ids.

        A secret found only by the deep-JS SecurityAuditor (``source='secret-audit'``)
        becomes a first-class secret finding but has no Scan Diff representation — the
        diff's secret section reads only the api phase — so the diff-based ``new_secret``
        alert never fires for it. This finding-based channel needs the same one-shot
        guard as SLA: fire per appearance exactly once across monitor runs, re-eligible
        after a ``REOPENED`` (a fixed secret that reappears alerts again). See
        ``_record_oneshot``.

        ``finding_ids`` are the project-scoped stored ids of the audit-only secret
        findings (from ``active_findings``). Returns the not-yet-alerted subset (now
        marked), in input order."""
        return self._record_oneshot(finding_ids, 'SECRET_ALERTED',
                                     scan_id=scan_id, now=now)

    def record_finding_alerts(self, project: str, finding_ids: List[str], *,
                              scan_id: Optional[str] = None,
                              now: Optional[str] = None) -> List[str]:
        """Mark generic high/critical findings as alerted *once* and return the
        newly-marked ids.

        A generic vuln finding (nuclei template, scanner check like SQLi/XSS, a
        non-dependency CVE) has no dedicated diff alert — unlike secret / takeover /
        source-map / GraphQL / cookie / dependency — so without this it surfaces only
        as an indirect ``risk_increase``. Finding-triggered, so it needs the same
        one-shot, reopen-resetting guard as the SLA / secret channels (see
        ``_record_oneshot``).

        ``finding_ids`` are the project-scoped stored ids of the alertable findings
        (from ``active_findings``). Returns the not-yet-alerted subset (now marked),
        in input order."""
        return self._record_oneshot(finding_ids, 'FINDING_ALERTED',
                                     scan_id=scan_id, now=now)

    def untracked_for_issue(self, project: str,
                            finding_ids: List[str]) -> List[str]:
        """Of ``finding_ids``, the ones with no *current* GitHub issue (read-only).

        The ``finding → issue`` mapping is an ``ISSUE_CREATED`` event carrying the
        issue number/url in ``note`` (no second table). A finding is considered
        untracked when it has no such event, or its latest one predates its latest
        ``REOPENED`` — same episode-aware semantics as the one-shot guard: a fixed
        finding that reappears needs a fresh issue. Returns the pending subset in
        input order. ``project`` is accepted for symmetry/call-site clarity; the ids
        are already project-scoped."""
        ids = list(dict.fromkeys(str(i) for i in (finding_ids or []) if i))
        if not ids:
            return []
        placeholders = ','.join('?' * len(ids))
        with self._connect() as conn:
            def latest(et: str) -> Dict[str, str]:
                rows = conn.execute(
                    f'SELECT finding_id fid, MAX(at) at FROM finding_events'
                    f' WHERE type = ? AND finding_id IN ({placeholders})'
                    f' GROUP BY finding_id', (et, *ids)).fetchall()
                return {r['fid']: r['at'] for r in rows}

            issued_at, reopen_at = latest('ISSUE_CREATED'), latest('REOPENED')
        pending: List[str] = []
        for fid in ids:
            issued = issued_at.get(fid)
            reopened = reopen_at.get(fid)
            tracked = issued is not None and (reopened is None or issued > reopened)
            if not tracked:
                pending.append(fid)
        return pending

    def record_issue(self, project: str, finding_id: str, number: int, url: str, *,
                     scan_id: Optional[str] = None,
                     now: Optional[str] = None) -> None:
        """Persist the ``finding → GitHub issue`` mapping as an ``ISSUE_CREATED``
        event (``note`` = ``{"number", "url"}``). Recorded only after the issue is
        actually created, so a failed API call leaves the finding untracked and
        eligible to retry. No new table — the mapping lives in ``finding_events``."""
        note = json.dumps({'number': number, 'url': url})
        with self._connect() as conn:
            self._log_event(conn, str(finding_id), 'ISSUE_CREATED',
                            scan_id=scan_id, note=note, at=now or _now())

    # ── remediation tasks (F4) — event-sourced over finding_events ────────────

    def set_remediation(self, finding_id: str, payload: Dict, *,
                        scan_id: Optional[str] = None,
                        now: Optional[str] = None) -> None:
        """Append a remediation-task state change as a ``REMEDIATION`` event.

        The task (``note`` = its JSON: status/owner/due/note) is event-sourced — its
        current state is the latest such event (see :meth:`get_remediation`) — so
        there is no second table and the full edit history stays in
        ``finding_events`` (mirrors the ``ISSUE_CREATED`` mapping)."""
        with self._connect() as conn:
            self._log_event(conn, str(finding_id), 'REMEDIATION', scan_id=scan_id,
                            note=json.dumps(payload or {}, ensure_ascii=False),
                            at=now or _now())

    def get_remediation(self, finding_id: str) -> Optional[Dict]:
        """The current remediation task for a finding (the latest ``REMEDIATION``
        event's payload), or ``None`` if no task was ever set."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT note FROM finding_events WHERE finding_id = ?"
                " AND type = 'REMEDIATION' ORDER BY id DESC LIMIT 1",
                (str(finding_id),)).fetchone()
        if row is None or not row['note']:
            return None
        try:
            return json.loads(row['note'])
        except (ValueError, TypeError):
            return None

    def remediations(self, project: str) -> List[Dict]:
        """Every finding in ``project`` with a remediation task, carrying the current
        task payload + the finding's title/severity/category/status (latest event per
        finding wins). The Remediation view's source — joins ``finding_events`` to
        ``findings``, no second table."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT e.finding_id, e.note, e.at, f.title, f.severity, f.category,"
                " f.status FROM finding_events e JOIN findings f"
                " ON f.id = e.finding_id WHERE f.project = ? AND e.type ="
                " 'REMEDIATION' ORDER BY e.id", (project,)).fetchall()
        latest: Dict[str, Dict] = {}
        for r in rows:
            try:
                task = json.loads(r['note']) if r['note'] else {}
            except (ValueError, TypeError):
                task = {}
            latest[r['finding_id']] = {
                'finding_id': r['finding_id'], 'title': r['title'],
                'severity': r['severity'], 'category': r['category'],
                'finding_status': r['status'], 'updated_at': r['at'], 'task': task,
            }
        return list(latest.values())

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
