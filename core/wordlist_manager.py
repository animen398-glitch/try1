"""Context-Aware Wordlist Manager (Roadmap E5).

Turn *what a scan already fingerprinted* (technologies) plus the engagement's
Rules of Engagement into a **small, targeted, budget-bounded** list of paths
worth checking — the opposite of a blind mega-dictionary brute force. This is a
pure **planner**: it selects and caps candidates; it never sends a request, and
it refuses to plan active probing when the ROE is passive-only. Un-throttled
brute forcing is explicitly out of scope (``core.action_policy`` forbids it).

Design
------
- Pure / offline / stdlib-only. Curated, precision-first dictionaries (high-signal
  paths only), the same ethos as :mod:`core.secret_scanner`.
- The request budget is derived from the ROE ``rate_limit`` via the SSOT
  :func:`utils.host_throttle.rate_per_sec`, so a plan can never exceed what the
  authorized rate allows over the planning window.
- Composes with the existing layers: technologies come from the recon
  fingerprint, the ROE from :mod:`core.audit_scope`. No new scanner, no network.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from utils.host_throttle import rate_per_sec


# Curated, high-signal path dictionaries. Small on purpose — targeted checks, not
# a brute-force list. ``generic`` / ``config`` / ``vcs`` form the safe baseline;
# the rest are added only when the matching technology is detected.
_WORDLISTS: Dict[str, tuple] = {
    "generic": (
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/admin", "/login", "/status", "/health",
    ),
    "config": (
        "/.env", "/config.php.bak", "/config.json", "/backup.zip",
        "/.env.local", "/settings.py.bak",
    ),
    "vcs": (
        "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/store",
    ),
    "api": (
        "/api", "/api/v1", "/graphql", "/swagger.json", "/openapi.json",
        "/.well-known/openid-configuration",
    ),
    "wordpress": (
        "/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/users",
        "/wp-config.php.bak", "/xmlrpc.php",
    ),
    "php": ("/info.php", "/phpinfo.php", "/test.php"),
    "django": ("/admin/", "/static/admin/", "/__debug__/"),
    "laravel": ("/telescope", "/.env", "/storage/logs/laravel.log"),
    "spring": ("/actuator", "/actuator/health", "/actuator/env"),
    "nodejs": ("/.npmrc", "/package.json", "/server.js.map"),
    "tomcat": ("/manager/html", "/host-manager/html", "/examples/"),
}

# Baseline categories always included (safe, few, high-value).
_BASELINE = ("generic", "config", "vcs")

# Substrings of a detected technology name → the extra category it unlocks.
_TECH_CATEGORY = {
    "wordpress": "wordpress",
    "woocommerce": "wordpress",
    "php": "php",
    "django": "django",
    "laravel": "laravel",
    "spring": "spring",
    "node": "nodejs",
    "express": "nodejs",
    "tomcat": "tomcat",
    "graphql": "api",
    "swagger": "api",
    "openapi": "api",
    "fastapi": "api",
}

# A conservative default cap when the ROE declares no rate limit, and a hard
# ceiling so even a generous rate can never plan an unreasonable sweep.
_DEFAULT_BUDGET = 50
_MAX_BUDGET = 500


def _tech_names(technologies: Any) -> List[str]:
    """Lower-cased technology names from a report's ``technologies`` list.

    Tolerates both ``[{'name': 'WordPress'}]`` and ``['WordPress']`` shapes.
    """
    out: List[str] = []
    for item in technologies or []:
        name = item.get("name") if isinstance(item, dict) else item
        text = str(name or "").strip().lower()
        if text:
            out.append(text)
    return out


def technologies_from_report(report: Dict[str, Any]) -> List[str]:
    """Extract detected technology names from a scan report (best-effort)."""
    if not isinstance(report, dict):
        return []
    recon = (report.get("phases") or {}).get("recon")
    data = recon.get("data") if isinstance(recon, dict) else None
    data = data if isinstance(data, dict) else {}
    names = _tech_names(data.get("technologies"))
    names.extend(str(c).strip().lower() for c in (data.get("cms") or []) if c)
    return names


def categories_for(technologies: Any) -> List[str]:
    """The path categories relevant to a set of detected technologies.

    Always the safe baseline (generic/config/vcs) plus any technology-specific
    category unlocked by a detected name. Stable, de-duplicated order.
    """
    cats: List[str] = list(_BASELINE)
    for name in _tech_names(technologies):
        for marker, category in _TECH_CATEGORY.items():
            if marker in name and category not in cats:
                cats.append(category)
    return cats


def select_paths(technologies: Any, *, extra_categories: Optional[List[str]] = None) -> List[str]:
    """The de-duplicated, ordered candidate paths for these technologies.

    Baseline + technology-specific categories, plus any explicit
    ``extra_categories``. Order is category order then in-list order, so the plan
    is deterministic.
    """
    cats = categories_for(technologies)
    for extra in extra_categories or []:
        key = str(extra).strip().lower()
        if key in _WORDLISTS and key not in cats:
            cats.append(key)
    seen: set[str] = set()
    paths: List[str] = []
    for cat in cats:
        for path in _WORDLISTS.get(cat, ()):
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def budget_from_roe(roe: Optional[Dict[str, Any]], *, window_s: int = 60) -> int:
    """Max candidate requests allowed by the ROE rate limit over ``window_s``.

    ``rate_per_sec × window_s``, floored at 1 and capped at ``_MAX_BUDGET``. When
    the ROE declares no rate limit, a conservative ``_DEFAULT_BUDGET`` is used
    (targeted checks, never an open-ended sweep).
    """
    rate = rate_per_sec((roe or {}).get("rate_limit"))
    if rate <= 0:
        return _DEFAULT_BUDGET
    return max(1, min(_MAX_BUDGET, int(rate * max(1, int(window_s)))))


def plan_wordlist(
    technologies: Any,
    roe: Optional[Dict[str, Any]] = None,
    *,
    max_candidates: Optional[int] = None,
    window_s: int = 60,
    extra_categories: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a ROE-budgeted, technology-targeted candidate plan (pure planning).

    Returns ``{authorized, reason, candidates, total_available, budget,
    truncated, categories}``. It is **authorized only for active-enabled,
    non-passive ROE** — a passive-only or active-disabled ROE yields an empty
    plan (``authorized=False``) because probing paths is an active action. The
    candidate list is capped to the smaller of the ROE budget and any explicit
    ``max_candidates``. Nothing is ever requested here.
    """
    from core.audit_scope import normalize_roe

    normalized = normalize_roe(roe)
    cats = categories_for(technologies)
    for extra in extra_categories or []:
        key = str(extra).strip().lower()
        if key in _WORDLISTS and key not in cats:
            cats.append(key)

    if normalized["passive_only"] or not normalized["active_scan_enabled"]:
        return {
            "authorized": False,
            "reason": "ROE is passive-only; path probing is an active action",
            "candidates": [],
            "total_available": len(select_paths(technologies, extra_categories=extra_categories)),
            "budget": 0,
            "truncated": False,
            "categories": cats,
        }

    all_paths = select_paths(technologies, extra_categories=extra_categories)
    budget = budget_from_roe(normalized, window_s=window_s)
    cap = budget if max_candidates is None else min(budget, max(0, int(max_candidates)))
    candidates = all_paths[:cap]
    return {
        "authorized": True,
        "reason": "",
        "candidates": candidates,
        "total_available": len(all_paths),
        "budget": budget,
        "truncated": len(candidates) < len(all_paths),
        "categories": cats,
    }
