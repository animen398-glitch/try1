"""core/project.py
Project workspace — the platform's unit of work.

Advanced Site Analyzer is moving from "a bag of one-off scans" to "a project you
revisit". A *project* is one target (a domain) with a durable home on disk:

    <base>/Projects/<slug>/
        scans/<timestamp>/   ← each Full Collection run (its existing layout,
                                untouched: recon/ api/ capture/ … report.html)
        reports/             ← project-level rollups (future use)
        screenshots/         ← project-level captures (future use)
        exports/             ← user exports (future use)
        history/<id>.json    ← one snapshot per scan (risk verdict + metrics)
        metadata.json        ← index of every scan + the latest verdict

This is the "Project owns timestamped scans" model: a scan's directory is
nested under the project but its internal structure is identical to before, so
every existing reader (report.html, report.json) keeps working — no migration.

Pure / stdlib-only and offline (architectural invariants I1/I2/I5): all logic
lives here so the GUI stays a thin viewer (I4), and ``metadata.json`` is the
single source of truth for a project's scan list (I3).
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

PROJECTS_DIRNAME = 'Projects'
METADATA_NAME = 'metadata.json'
_SUBDIRS = ('scans', 'reports', 'screenshots', 'exports', 'history')


def project_slug(url_or_domain: str) -> str:
    """Canonical project slug for a URL or bare domain.

    The single source of truth for target-folder naming (``collection_runner``
    delegates here). ``https://www.Example.com/path`` → ``Example.com``;
    ``http://sub.example.org:8080`` → ``sub.example.org_8080``.
    """
    netloc = urlparse(url_or_domain).netloc or url_or_domain.split('/')[0]
    slug = re.sub(r'^www\.', '', netloc)
    return re.sub(r'[^\w.-]', '_', slug) or 'site'


class Project:
    """One target's durable workspace under ``Projects/<slug>/``."""

    def __init__(self, root: Union[str, Path], url: str = ''):
        self.root = Path(root)
        self.slug = self.root.name
        self.url = url

    # ---------------------------------------------------------------- layout
    @property
    def metadata_path(self) -> Path:
        return self.root / METADATA_NAME

    def ensure(self) -> 'Project':
        """Create the directory skeleton + a metadata.json if absent."""
        for d in _SUBDIRS:
            (self.root / d).mkdir(parents=True, exist_ok=True)
        if not self.metadata_path.exists():
            self._write_metadata(self._new_metadata())
        return self

    def _new_metadata(self) -> Dict:
        from core.scope_guard import default_scope_for_target
        now = datetime.now().isoformat(timespec='seconds')
        return {'slug': self.slug, 'url': self.url, 'created_at': now,
                'updated_at': now, 'scan_count': 0, 'latest_scan': None,
                'scans': [], 'scope': default_scope_for_target(self.url)}

    # ---------------------------------------------------------------- metadata
    def load_metadata(self) -> Dict:
        try:
            return json.loads(self.metadata_path.read_text(encoding='utf-8'))
        except Exception:
            return self._new_metadata()

    def _write_metadata(self, meta: Dict) -> None:
        self.metadata_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8')

    # ---------------------------------------------------------------- scans
    def start_scan(self, stamp: Optional[str] = None) -> Path:
        """Create and return ``scans/<timestamp>/`` for a new run."""
        self.ensure()
        stamp = stamp or datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_dir = self.root / 'scans' / stamp
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    @staticmethod
    def _scan_entry(scan_dir: Path, report: Dict) -> Dict:
        """Flatten a finished collection ``report`` into an index entry."""
        scan_id = Path(scan_dir).name
        es = report.get('executive_summary') or {}
        metrics = es.get('metrics', {}) if isinstance(es, dict) else {}
        warnings = report.get('warnings') if isinstance(report.get('warnings'), list) else []
        status = report.get('status') or (
            'Cancelled' if report.get('cancelled') else 'Success')
        return {
            'id': scan_id,
            # Forward-slash relative locator (portable across OSes / JSON).
            'dir': (Path('scans') / scan_id).as_posix(),
            'url': report.get('url'),
            'started_at': report.get('started_at'),
            'finished_at': report.get('finished_at'),
            'status': status,
            'risk_level': es.get('risk_level'),
            'risk_score': es.get('risk_score'),
            'attack_surface_score': metrics.get('attack_surface_score'),
            'secrets': metrics.get('secrets'),
            'high': metrics.get('high'),
            'medium': metrics.get('medium'),
            # Detection-category breakdown for the exposure heatmap (F5). Already
            # derived in the executive summary — persisted here so the portfolio
            # reads them from cheap metadata.json, not every report.json (I3).
            'source_map_leaks': metrics.get('source_map_leaks'),
            'weak_cookies': metrics.get('weak_cookies'),
            'graphql': metrics.get('graphql'),
            'graphql_introspection': metrics.get('graphql_introspection'),
            'warning_count': len(warnings),
            'report_html': report.get('report_html'),
            'report_json': report.get('report_json'),
        }

    def record_scan(self, scan_dir: Path, report: Dict) -> Dict:
        """Index a finished scan: update ``metadata.json`` and drop a
        ``history/<id>.json`` snapshot. Idempotent — re-recording the same scan
        id replaces its entry rather than duplicating it. Returns the entry."""
        entry = self._scan_entry(scan_dir, report)
        meta = self.load_metadata()
        meta['scans'] = [s for s in meta.get('scans', [])
                         if s.get('id') != entry['id']]
        meta['scans'].append(entry)
        meta['scans'].sort(key=lambda s: s.get('id') or '')
        meta['scan_count'] = len(meta['scans'])
        # Scans are sorted by id (a timestamp), so the newest scan is last.
        meta['latest_scan'] = meta['scans'][-1]
        meta['updated_at'] = datetime.now().isoformat(timespec='seconds')
        if not meta.get('url'):
            meta['url'] = report.get('url')
        self._write_metadata(meta)
        try:
            hist = self.root / 'history'
            hist.mkdir(parents=True, exist_ok=True)
            (hist / f"{entry['id']}.json").write_text(
                json.dumps(entry, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8')
        except Exception:
            pass   # a history snapshot is best-effort; never fail a scan over it
        return entry

    def scans(self) -> List[Dict]:
        return self.load_metadata().get('scans', [])

    def load_scan_report(self, scan_id: str) -> Optional[Dict]:
        """Full ``report.json`` of one scan, or ``None`` if absent/corrupt.

        The single place that knows where a scan's report lives (I3) — e.g.
        ``core.scan_diff`` stays a pure function over the dicts this returns.
        """
        path = self.root / 'scans' / scan_id / 'report.json'
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return None

    def latest_scan(self) -> Optional[Dict]:
        return self.load_metadata().get('latest_scan')

    # ---------------------------------------------------------------- monitoring
    def get_monitor(self) -> Optional[Dict]:
        """The project's Continuous Monitoring schedule, or None if unset.

        The schedule (cadence + next-run) lives in ``metadata.json`` so it
        survives across runs alongside the scan index (I3). ``core.monitor``
        owns its shape; Project only persists it."""
        mon = self.load_metadata().get('monitor')
        return mon if isinstance(mon, dict) else None

    def set_monitor(self, config: Optional[Dict]) -> None:
        """Store (or, with ``None``, clear) the monitoring schedule.

        Read-modify-write so it composes with ``record_scan`` (both load the
        whole metadata and write it back, preserving each other's keys)."""
        self.ensure()
        meta = self.load_metadata()
        if config is None:
            meta.pop('monitor', None)
        else:
            meta['monitor'] = config
        meta['updated_at'] = datetime.now().isoformat(timespec='seconds')
        self._write_metadata(meta)

    # ---------------------------------------------------------------- company
    def get_company(self) -> Optional[str]:
        """The project's company slug, or None when unassigned (Epic F-C1).

        Company membership is a logical label stored as a single optional key in
        ``metadata.json`` — never a directory layer (see ``core.company``)."""
        company = self.load_metadata().get('company')
        return company if isinstance(company, str) and company.strip() else None

    def set_company(self, company: Optional[str]) -> None:
        """Assign (or, with a falsy value, clear) the project's company slug.

        Read-modify-write, composing with ``record_scan``/``set_monitor`` (each
        preserves the others' keys). The value is a company *slug*
        (``core.company.company_slug``); the caller owns any registry entity."""
        self.ensure()
        meta = self.load_metadata()
        if company and str(company).strip():
            meta['company'] = str(company).strip()
        else:
            meta.pop('company', None)
        meta['updated_at'] = datetime.now().isoformat(timespec='seconds')
        self._write_metadata(meta)

    # ---------------------------------------------------------------- scope
    def get_scope(self) -> Dict:
        """The project's Scope Guard config.

        Missing ``scope`` is normalized to a legacy-safe default: no explicit
        allowlist/denylist, active opt-in phases enabled, and no rate-limit
        enforcement. Callers can still surface this default explicitly in reports.
        """
        from core.scope_guard import normalize_scope
        return normalize_scope(self.load_metadata().get('scope'))

    def set_scope(self, config: Optional[Dict]) -> None:
        """Store (or, with ``None``, clear) the project Scope Guard config.

        Read-modify-write so it composes with ``record_scan``/``set_monitor`` and
        keeps ``Projects/<slug>/metadata.json`` as the only project-level file.
        """
        from core.scope_guard import normalize_scope
        self.ensure()
        meta = self.load_metadata()
        if config is None:
            meta.pop('scope', None)
        else:
            meta['scope'] = normalize_scope(config)
        meta['updated_at'] = datetime.now().isoformat(timespec='seconds')
        self._write_metadata(meta)


class ProjectStore:
    """Manages the ``<base>/Projects/`` tree of projects."""

    def __init__(self, base: Union[str, Path]):
        # Projects live under the user's configured output base so existing
        # reports stay where users expect them (not hidden in app-data).
        self.root = Path(base).expanduser() / PROJECTS_DIRNAME

    def get_or_create(self, url: str) -> Project:
        project = Project(self.root / project_slug(url), url=url)
        return project.ensure()

    def get(self, slug: str) -> Optional[Project]:
        d = self.root / slug
        return Project(d) if (d / METADATA_NAME).exists() else None

    def list_projects(self) -> List[Dict]:
        """Every project's metadata, newest-updated first (for a Projects view)."""
        out: List[Dict] = []
        if not self.root.is_dir():
            return out
        for d in sorted(self.root.iterdir()):
            if d.is_dir() and (d / METADATA_NAME).exists():
                out.append(Project(d).load_metadata())
        out.sort(key=lambda m: m.get('updated_at') or '', reverse=True)
        return out

    # ---------------------------------------------------------------- company
    def companies(self) -> List[Dict]:
        """Projects grouped by company (derive-on-read, Epic F-C1).

        Thin loader over ``list_projects`` + the company registry — mirrors the
        portfolio split (pure aggregator in ``core.company`` + this loader). One
        entry per company, with the implicit ``Unassigned`` bucket last."""
        from core.company import CompanyRegistry, group_projects
        return group_projects(self.list_projects(), CompanyRegistry())

    def assign(self, slug: str, company: Optional[str]) -> bool:
        """Set (or clear) a project's company membership; True if the project
        exists. ``company`` is a company slug (or falsy to unassign)."""
        project = self.get(slug)
        if project is None:
            return False
        project.set_company(company)
        return True
