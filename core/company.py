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
