"""core/company.py
Company / Workspace tier — the grouping dimension above projects (Epic F-C1).

The platform's hierarchy is ``Company → Projects → Scans → Findings/Assets``. A
*company* groups several per-domain projects (e.g. "Acme Corp" = ``acme.com`` +
``api.acme.io`` + ``acme-cdn.net``) so risk / findings / assets can roll up to the
organisation.

Design (the central decision of this epic — see the plan):

  * **Membership is a logical label, never a directory layer.** The
    ``Projects/<slug>/`` layout stays flat and untouched; a project's company is
    a single optional ``company`` key in its ``metadata.json`` (read/written by
    ``Project.get_company``/``set_company``, mirroring the existing ``monitor``
    key). A project with no ``company`` belongs to the implicit ``Unassigned``
    company — so every pre-tier project keeps working with no migration.

  * **This module owns only company *entities*** — display name + attributes —
    in a thin JSON registry (``data/companies.json``). It deliberately does NOT
    store membership (that lives on the project, the single source of truth), so
    the two can never drift. A company referenced by a project but missing from
    the registry degrades gracefully to its slug as the name.

Pure / stdlib-only and offline (architectural invariants I1/I2/I5): the registry
is a small JSON file, grouping is derive-on-read over already-loaded project
metadata (no second table, mirroring F2/F5).
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

from core.config import COMPANIES_REGISTRY

# Sentinel slug + label for projects with no company assigned. The slug is a
# reserved value that ``company_slug`` can never produce (leading underscores are
# stripped), so it cannot collide with a real company.
UNASSIGNED = '__unassigned__'
UNASSIGNED_LABEL = 'Unassigned'


def company_slug(name: str) -> str:
    """Canonical, key/filesystem-safe slug for a company display name.

    The single source of truth for company keys (registry keys + the project's
    ``company`` field). ``"Acme Corp"`` → ``acme_corp``; lower-cased, non-word
    runs collapsed to ``_``. Returns ``''`` for an empty/garbage name so callers
    can treat that as "no company".
    """
    slug = re.sub(r'[^\w.-]+', '_', str(name or '').strip().lower())
    return slug.strip('_.-')


class CompanyRegistry:
    """Thin JSON store of company entities (name + attributes), not membership."""

    def __init__(self, path: Optional[Union[str, Path]] = None):
        self.path = Path(path) if path is not None else Path(COMPANIES_REGISTRY)

    # ----------------------------------------------------------- persistence
    def _load(self) -> Dict[str, Dict]:
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save(self, data: Dict[str, Dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8')

    # ----------------------------------------------------------- reads
    def list(self) -> List[Dict]:
        """All registered companies (slug + name + attrs), name-sorted."""
        out = [self._entry(slug, rec) for slug, rec in self._load().items()]
        out.sort(key=lambda c: (c.get('name') or '').lower())
        return out

    def get(self, slug: str) -> Optional[Dict]:
        rec = self._load().get(company_slug(slug) or slug)
        return self._entry(company_slug(slug) or slug, rec) if rec else None

    def display_name(self, slug: str) -> str:
        """Friendly name for a company slug, falling back to the slug itself.

        ``UNASSIGNED`` maps to its label so the grouping view always has a name.
        """
        if not slug or slug == UNASSIGNED:
            return UNASSIGNED_LABEL
        rec = self._load().get(slug)
        return (rec or {}).get('name') or slug

    @staticmethod
    def _entry(slug: str, rec: Dict) -> Dict:
        rec = rec or {}
        return {'slug': slug, 'name': rec.get('name') or slug,
                'created_at': rec.get('created_at'),
                'tags': rec.get('tags') or []}

    # ----------------------------------------------------------- writes
    def create(self, name: str) -> str:
        """Create a company from a display ``name``; return its slug.

        Idempotent — an existing slug keeps its record (and refreshes the display
        name if a new casing/spelling is given). Raises ``ValueError`` on an empty
        name so the caller surfaces it rather than silently making a blank key.
        """
        slug = company_slug(name)
        if not slug:
            raise ValueError('company name is empty')
        data = self._load()
        rec = data.get(slug) or {
            'created_at': datetime.now().isoformat(timespec='seconds')}
        rec['name'] = str(name).strip()
        data[slug] = rec
        self._save(data)
        return slug

    def rename(self, slug: str, name: str) -> None:
        """Set the display name of an existing company (no slug change)."""
        slug = company_slug(slug) or slug
        data = self._load()
        if slug in data:
            data[slug]['name'] = str(name).strip()
            self._save(data)

    def delete(self, slug: str) -> None:
        """Remove a company entity. Membership on projects is untouched — an
        orphaned reference degrades to the slug as its name."""
        slug = company_slug(slug) or slug
        data = self._load()
        if data.pop(slug, None) is not None:
            self._save(data)


def group_projects(projects_meta: List[Dict],
                   registry: Optional[CompanyRegistry] = None) -> List[Dict]:
    """Group project metadata by company (derive-on-read, pure).

    ``projects_meta`` is the list of ``metadata.json`` dicts from
    ``ProjectStore.list_projects`` (newest-updated first). Returns one entry per
    company — ``{slug, name, project_count, project_slugs, updated_at}`` — with
    the implicit ``Unassigned`` bucket for projects with no ``company`` field.
    Companies are sorted with ``Unassigned`` last, then by most-recent activity.
    """
    registry = registry or CompanyRegistry()
    groups: Dict[str, Dict] = {}
    for meta in projects_meta or []:
        if not isinstance(meta, dict):
            continue
        slug = (meta.get('company') or '').strip() or UNASSIGNED
        g = groups.get(slug)
        if g is None:
            g = groups[slug] = {
                'slug': slug,
                'name': registry.display_name(slug),
                'project_count': 0,
                'project_slugs': [],
                'updated_at': '',
            }
        g['project_count'] += 1
        if meta.get('slug'):
            g['project_slugs'].append(meta['slug'])
        updated = meta.get('updated_at') or ''
        if updated > g['updated_at']:
            g['updated_at'] = updated

    out = list(groups.values())
    # Two stable passes: newest activity first, then partition Unassigned last.
    out.sort(key=lambda c: c['updated_at'], reverse=True)
    out.sort(key=lambda c: c['slug'] == UNASSIGNED)
    return out


def build_company_rollup(projects_meta: List[Dict],
                         active_findings: Optional[Dict[str, int]] = None,
                         assets_by_project: Optional[Dict[str, Dict[str, int]]] = None,
                         registry: Optional[CompanyRegistry] = None) -> Dict:
    """Fold per-project portfolio rows up to the company level (pure, F-C2).

    Reuses ``portfolio.build_portfolio`` for the per-project numbers (no recompute
    — I3), then aggregates them by each project's ``company`` field:

      * risk     — worst level + worst (max) score across the company's projects;
      * risk_delta — sum of the projects' deltas (None until at least one exists);
      * secrets/high/medium/active_findings — summed;
      * attack_surface — worst (max) across projects;
      * assets   — per-type counts summed from ``assets_by_project`` (+ total).

    ``assets_by_project`` maps a project slug to its ``AssetStore.summary``
    ``by_type`` dict. Returns ``{rows, totals}`` mirroring ``build_portfolio`` —
    ``rows`` are per-company snapshots (worst risk first, Unassigned last) and
    ``totals`` is the estate roll-up.
    """
    from core.executive_summary import RISK_COLORS, RISK_ORDER
    from core.portfolio import build_portfolio

    registry = registry or CompanyRegistry()
    assets_by_project = assets_by_project or {}
    rank = {level: i for i, level in enumerate(RISK_ORDER)}

    # Per-project rows (already display-ready) + slug→company from the metadata.
    rows = build_portfolio(projects_meta, active_findings).get('rows', [])
    company_of = {}
    for meta in projects_meta or []:
        if isinstance(meta, dict) and meta.get('slug'):
            company_of[meta['slug']] = (
                (meta.get('company') or '').strip() or UNASSIGNED)

    groups: Dict[str, Dict] = {}
    for r in rows:
        slug = company_of.get(r.get('slug'), UNASSIGNED)
        g = groups.get(slug)
        if g is None:
            g = groups[slug] = {
                'slug': slug, 'name': registry.display_name(slug),
                'project_count': 0, 'project_slugs': [],
                'risk_level': None, 'risk_score': None, 'risk_delta': None,
                'attack_surface': None, 'secrets': 0, 'high': 0, 'medium': 0,
                'active_findings': 0, 'assets': {}, 'asset_total': 0,
                'updated_at': '',
            }
        g['project_count'] += 1
        if r.get('slug'):
            g['project_slugs'].append(r['slug'])
        # Worst risk level / score across the company's projects.
        lvl = r.get('risk_level')
        if lvl in rank and (g['risk_level'] is None
                            or rank[lvl] < rank[g['risk_level']]):
            g['risk_level'] = lvl
        g['risk_score'] = _max_opt(g['risk_score'], r.get('risk_score'))
        g['attack_surface'] = _max_opt(g['attack_surface'], r.get('attack_surface'))
        g['risk_delta'] = _sum_opt(g['risk_delta'], r.get('risk_delta'))
        for key in ('secrets', 'high', 'medium', 'active_findings'):
            g[key] += _int0(r.get(key))
        for atype, count in (assets_by_project.get(r.get('slug')) or {}).items():
            g['assets'][atype] = g['assets'].get(atype, 0) + _int0(count)
            g['asset_total'] += _int0(count)
        if (r.get('updated_at') or '') > g['updated_at']:
            g['updated_at'] = r.get('updated_at') or ''

    out = list(groups.values())
    for g in out:
        g['risk_color'] = RISK_COLORS.get(g['risk_level'], '#888')
    # Worst risk first, Unassigned last (two stable passes).
    out.sort(key=lambda c: (_num(c['risk_score']) or 0.0), reverse=True)
    out.sort(key=lambda c: c['slug'] == UNASSIGNED)

    worst = None
    for g in out:
        lvl = g['risk_level']
        if lvl in rank and (worst is None or rank[lvl] < rank[worst]):
            worst = lvl
    totals = {
        'companies': len(out),
        'projects': sum(g['project_count'] for g in out),
        'worst_risk_level': worst,
        'worst_risk_color': RISK_COLORS.get(worst, '#888'),
        'secrets': sum(g['secrets'] for g in out),
        'high': sum(g['high'] for g in out),
        'medium': sum(g['medium'] for g in out),
        'active_findings': sum(g['active_findings'] for g in out),
        'assets': sum(g['asset_total'] for g in out),
    }
    return {'rows': out, 'totals': totals}


def _int0(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _num(value) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _max_opt(current, candidate):
    """Max of two optional numerics, preserving None when both are missing."""
    c, n = _num(current), _num(candidate)
    if c is None:
        return candidate if n is not None else current
    if n is None:
        return current
    return candidate if n > c else current


def _sum_opt(current, candidate):
    """Sum of two optional numerics, None only when both are missing."""
    c, n = _num(current), _num(candidate)
    if c is None and n is None:
        return None
    return (c or 0.0) + (n or 0.0)


def load_company_view(base: str) -> Dict:
    """Load the company roll-up for the projects tree under ``base`` (thin loader).

    Gathers each project's metadata (carrying its ``company`` field), the active-
    findings map (shared with the portfolio loader) and per-project asset
    by-type counts, then delegates to the pure aggregator. Offline, read-only;
    run it off the GUI thread (I4). Asset counts are best-effort — a store
    failure degrades to empty rather than sinking the view.
    """
    from core.portfolio import active_findings_map
    from core.project import ProjectStore

    projects_meta = ProjectStore(base).list_projects()
    assets_by_project: Dict[str, Dict[str, int]] = {}
    try:
        from core.asset_store import AssetStore
        store = AssetStore()
        for meta in projects_meta:
            slug = meta.get('slug')
            if slug:
                assets_by_project[slug] = store.summary(slug).get('by_type', {})
    except Exception:   # noqa: BLE001 — assets are best-effort for the roll-up
        assets_by_project = {}
    return build_company_rollup(projects_meta, active_findings_map(),
                                assets_by_project, CompanyRegistry())
