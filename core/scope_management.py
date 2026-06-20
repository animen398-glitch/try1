"""Project Scope Guard management helpers.

Pure helpers for local CLI/web callers. Scope still lives on the Project
metadata.json; this module only centralizes lookup, patching, and response shape
so command-line wrappers stay thin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from core.project import ProjectStore
from core.scope_guard import normalize_scope


def _project(store: ProjectStore, target: str, *, create: bool = False):
    if create:
        return store.get_or_create(target)
    slug = target
    if "://" in target or "/" in target:
        slug = store.get_or_create(target).slug
    project = store.get(slug)
    if project is None:
        raise KeyError(f"project not found: {target}")
    return project


def show_scope(store: ProjectStore, target: str, *, create: bool = False) -> Dict[str, Any]:
    project = _project(store, target, create=create)
    meta = project.load_metadata()
    return {
        "slug": project.slug,
        "url": meta.get("url") or project.url,
        "explicit": isinstance(meta.get("scope"), dict),
        "scope": project.get_scope(),
    }


def patch_scope(
    current: Optional[Dict[str, Any]],
    *,
    allowed_domains: Optional[list[str]] = None,
    denied_domains: Optional[list[str]] = None,
    active_scan_enabled: Optional[bool] = None,
    passive_only: Optional[bool] = None,
    rate_limit: Any = None,
    clear_rate_limit: bool = False,
) -> Dict[str, Any]:
    scope = normalize_scope(current)
    if allowed_domains is not None:
        scope["allowed_domains"] = allowed_domains
    if denied_domains is not None:
        scope["denied_domains"] = denied_domains
    if active_scan_enabled is not None:
        scope["active_scan_enabled"] = active_scan_enabled
    if passive_only is not None:
        scope["passive_only"] = passive_only
    if clear_rate_limit:
        scope["rate_limit"] = None
    elif rate_limit is not None:
        scope["rate_limit"] = rate_limit
    return normalize_scope(scope)


def set_scope(
    store: ProjectStore,
    target: str,
    *,
    create: bool = True,
    allowed_domains: Optional[list[str]] = None,
    denied_domains: Optional[list[str]] = None,
    active_scan_enabled: Optional[bool] = None,
    passive_only: Optional[bool] = None,
    rate_limit: Any = None,
    clear_rate_limit: bool = False,
) -> Dict[str, Any]:
    project = _project(store, target, create=create)
    current = project.load_metadata().get("scope")
    scope = patch_scope(
        current,
        allowed_domains=allowed_domains,
        denied_domains=denied_domains,
        active_scan_enabled=active_scan_enabled,
        passive_only=passive_only,
        rate_limit=rate_limit,
        clear_rate_limit=clear_rate_limit,
    )
    project.set_scope(scope)
    return show_scope(store, project.slug)


def clear_scope(store: ProjectStore, target: str) -> Dict[str, Any]:
    project = _project(store, target, create=False)
    project.set_scope(None)
    return show_scope(store, project.slug)


def store_from_base(base: str | Path) -> ProjectStore:
    return ProjectStore(Path(base).expanduser())
