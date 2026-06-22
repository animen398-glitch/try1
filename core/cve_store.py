"""core/cve_store.py
CVE Intelligence persistence — a local SQLite cache for advisory lookups.

The offline foundation of CVE Intelligence (EPIC 3): once a ``(library, version)``
has been correlated and its CVEs enriched, the result is kept on disk so re-scans
work **without the network** — the "offline after the base is loaded" requirement.
No bundled CVE dump (that would bloat the ``.exe`` against invariant §2); the cache
fills lazily from the live providers (OSV + NVD) and is the source of truth on a
later offline run.

Two logical caches in one DB (``data/cve_cache.db`` via PathManager, frozen-aware):

  * ``lib_cves``     — ``(ecosystem, package, version)`` → the advisory list a
                       provider (OSV) returned for it.
  * ``cve_details``  — ``cve_id`` → the per-CVE enrichment (CVSS / severity /
                       published date / summary), deduplicated across libraries
                       since a CVE's score is the same everywhere it appears.

Design mirrors ``asset_store`` / ``findings_store`` exactly (no new paradigm):
built on ``SQLiteStore``, idempotent ``CREATE TABLE IF NOT EXISTS`` schema with
``PRAGMA user_version``. Each row stores ``fetched_at`` so the orchestrator can
decide freshness; a stale row is still returned (with its age) so an offline run
can fall back to it. Pure of network — the providers live elsewhere.
"""

from datetime import datetime
from typing import Dict, List, Optional, Union

from core.config import CVE_CACHE_DB
from utils.sqlite_store import SQLiteStore


def _now() -> str:
    return datetime.now().isoformat(timespec='seconds')


def _age_seconds(fetched_at: Optional[str]) -> float:
    """Seconds since ``fetched_at`` (ISO); a huge number if missing/unparseable
    (so a bad timestamp reads as "very stale", never "fresh")."""
    if not fetched_at:
        return float('inf')
    try:
        return max(0.0, (datetime.now()
                         - datetime.fromisoformat(str(fetched_at))).total_seconds())
    except (ValueError, TypeError):
        return float('inf')


def _lib_key(ecosystem: str, package: str, version: str) -> str:
    return f'{ecosystem}|{package}|{version}'


class CVEStore(SQLiteStore):
    """SQLite-backed persistent cache for CVE lookups + per-CVE enrichment."""

    JSON_FIELDS = ('vulns',)
    SCHEMA_VERSION = 1

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS lib_cves (
        key        TEXT PRIMARY KEY,
        vulns      TEXT NOT NULL,
        fetched_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_details (
        cve_id     TEXT PRIMARY KEY,
        cvss       REAL,
        severity   TEXT,
        published  TEXT,
        summary    TEXT,
        source     TEXT,
        fetched_at TEXT NOT NULL
    );
    """

    def __init__(self, db_path: Optional[Union[str, object]] = None):
        super().__init__(db_path or CVE_CACHE_DB)

    # ── (library, version) → advisory list ────────────────────────────────────

    def get_lib_cves(self, ecosystem: str, package: str,
                     version: str) -> Optional[Dict]:
        """Cached advisory list for a library, or ``None`` if never cached.

        Returns ``{'vulns': [...], 'age': seconds}`` — the caller decides whether
        the age is fresh enough, but a stale row is still returned so an offline
        run can fall back to it."""
        with self._connect() as conn:
            row = conn.execute('SELECT vulns, fetched_at FROM lib_cves WHERE key = ?',
                               (_lib_key(ecosystem, package, version),)).fetchone()
        if row is None:
            return None
        data = self._row_to_dict(row)
        return {'vulns': data.get('vulns') or [],
                'age': _age_seconds(data.get('fetched_at'))}

    def put_lib_cves(self, ecosystem: str, package: str, version: str,
                     vulns: List[Dict], *, now: Optional[str] = None) -> None:
        """Store (or refresh) the advisory list for a library."""
        import json
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO lib_cves (key, vulns, fetched_at) VALUES (?,?,?)'
                ' ON CONFLICT(key) DO UPDATE SET vulns = excluded.vulns,'
                ' fetched_at = excluded.fetched_at',
                (_lib_key(ecosystem, package, version),
                 json.dumps(vulns or [], ensure_ascii=False), now or _now()))

    # ── cve_id → enrichment (CVSS / severity / published / summary) ────────────

    def get_cve_detail(self, cve_id: str) -> Optional[Dict]:
        """Cached enrichment for one CVE, or ``None``. Adds ``age`` (seconds)."""
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM cve_details WHERE cve_id = ?',
                               (str(cve_id),)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data['age'] = _age_seconds(data.pop('fetched_at', None))
        return data

    def put_cve_detail(self, cve_id: str, detail: Dict, *,
                       now: Optional[str] = None) -> None:
        """Store (or refresh) the enrichment for one CVE."""
        d = detail or {}
        with self._connect() as conn:
            conn.execute(
                'INSERT INTO cve_details'
                ' (cve_id, cvss, severity, published, summary, source, fetched_at)'
                ' VALUES (?,?,?,?,?,?,?)'
                ' ON CONFLICT(cve_id) DO UPDATE SET cvss = excluded.cvss,'
                ' severity = excluded.severity, published = excluded.published,'
                ' summary = excluded.summary, source = excluded.source,'
                ' fetched_at = excluded.fetched_at',
                (str(cve_id), d.get('cvss'), d.get('severity'), d.get('published'),
                 d.get('summary'), d.get('source'), now or _now()))

    # ── maintenance ────────────────────────────────────────────────────────────

    def clear(self) -> int:
        """Drop every cached row; returns how many were removed (for the Settings
        'clear cache' action, like ``osv_correlation.clear_cache``)."""
        with self._connect() as conn:
            n = (conn.execute('SELECT COUNT(*) FROM lib_cves').fetchone()[0]
                 + conn.execute('SELECT COUNT(*) FROM cve_details').fetchone()[0])
            conn.execute('DELETE FROM lib_cves')
            conn.execute('DELETE FROM cve_details')
        return n

    def stats(self) -> Dict:
        """Row counts per table (for diagnostics / Settings display)."""
        with self._connect() as conn:
            return {
                'lib_cves': conn.execute('SELECT COUNT(*) FROM lib_cves').fetchone()[0],
                'cve_details': conn.execute(
                    'SELECT COUNT(*) FROM cve_details').fetchone()[0],
            }
