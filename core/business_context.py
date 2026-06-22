"""core/business_context.py
Business Context Model — user-declared asset importance (EPIC NEXT F1).

The platform scores assets *technically* (type weight, blast radius, attached
findings). But "which asset matters" is ultimately a **business** question only
the operator can answer: how critical is this asset to the business, and how
sensitive is the data it holds. F1 lets the user declare that, so downstream
impact scoring (``asset_criticality`` now; priority / attack-paths later) reflects
business reality, not just topology.

Design (mirrors the Company tier F-C1 — a label, never a directory/table):

  * Storage is a single additive ``business_context`` key in the project's
    ``metadata.json`` (read/written by ``Project.get/set_business_context``, like
    the existing ``monitor`` / ``company`` / ``scope`` keys). No new SQLite table,
    no second store — so every pre-F1 project keeps working with no migration.
  * Two grains: a project-level ``default`` (applies to the whole target) and
    per-asset ``assets`` overrides keyed by the asset's *bare* fingerprint
    (``asset_adapter.asset_fingerprint(type, value)``) — the same identity the
    inventory / criticality use, so an override joins cleanly on read.
  * This module is the single source of truth for the vocabulary, display labels,
    the additive weight each tier contributes to criticality, and the
    default+override resolution. Pure / stdlib-only / offline.

It is a display/impact-context layer: like criticality / exposure it AUGMENTS the
impact view and never touches the authoritative risk verdict
(``executive_summary._risk_level``).

Stored shape (normalized, empties dropped)::

    "business_context": {
        "default": {"criticality": "high", "data_sensitivity": "confidential"},
        "assets": {"<asset_fp>": {"criticality": "critical",
                                  "data_sensitivity": "restricted"}}
    }
"""

from typing import Dict, List, Optional

# Business-criticality tiers, highest first. None / absent = "not declared".
CRITICALITY_TIERS = ('critical', 'high', 'medium', 'low')
# Data-classification tiers, most sensitive first (standard 4-tier scheme).
DATA_SENSITIVITY = ('restricted', 'confidential', 'internal', 'public')

# Display labels (RU) — single source for the report card / CLI / future GUI.
CRITICALITY_LABELS = {'critical': 'Критичный для бизнеса', 'high': 'Высокий',
                      'medium': 'Средний', 'low': 'Низкий'}
SENSITIVITY_LABELS = {'restricted': 'Строго конфиденциально',
                      'confidential': 'Конфиденциально', 'internal': 'Внутреннее',
                      'public': 'Публичное'}

# Additive bonus to the asset_criticality score (0–100, capped by the caller).
# Business intent AUGMENTS the technical type-weight, it never replaces it (F1).
_CRITICALITY_WEIGHT = {'critical': 30, 'high': 20, 'medium': 10, 'low': 0}
_SENSITIVITY_WEIGHT = {'restricted': 20, 'confidential': 12, 'internal': 5,
                       'public': 0}


# ── vocabulary / normalization ────────────────────────────────────────────────

def normalize_criticality(value) -> Optional[str]:
    v = str(value or '').strip().lower()
    return v if v in _CRITICALITY_WEIGHT else None


def normalize_data_sensitivity(value) -> Optional[str]:
    v = str(value or '').strip().lower()
    return v if v in _SENSITIVITY_WEIGHT else None


def normalize_context(ctx) -> Dict[str, str]:
    """One ``{criticality?, data_sensitivity?}`` context, keeping only valid keys."""
    if not isinstance(ctx, dict):
        return {}
    out: Dict[str, str] = {}
    crit = normalize_criticality(ctx.get('criticality'))
    if crit:
        out['criticality'] = crit
    sens = normalize_data_sensitivity(ctx.get('data_sensitivity'))
    if sens:
        out['data_sensitivity'] = sens
    return out


def normalize_root(root) -> Dict:
    """Normalize the whole ``business_context`` blob to ``{default?, assets?}``.

    Drops empty contexts / the empty containers so ``metadata.json`` stays clean,
    and is tolerant of legacy/garbage shapes (returns ``{}``)."""
    root = root if isinstance(root, dict) else {}
    out: Dict = {}
    default = normalize_context(root.get('default'))
    if default:
        out['default'] = default
    assets: Dict[str, Dict] = {}
    raw = root.get('assets')
    if isinstance(raw, dict):
        for fp, ctx in raw.items():
            c = normalize_context(ctx)
            if c and isinstance(fp, str) and fp:
                assets[fp] = c
    if assets:
        out['assets'] = assets
    return out


# ── pure edit helpers (return a new normalized root) ──────────────────────────

def set_default(root, ctx) -> Dict:
    """Set (or, with an empty ctx, clear) the project-level default context."""
    out = normalize_root(root)
    ctx = normalize_context(ctx)
    if ctx:
        out['default'] = ctx
    else:
        out.pop('default', None)
    return normalize_root(out)


def set_asset(root, asset_fp, ctx) -> Dict:
    """Set (or, with an empty ctx, clear) a per-asset override by fingerprint."""
    out = normalize_root(root)
    assets = dict(out.get('assets') or {})
    ctx = normalize_context(ctx)
    if ctx and asset_fp:
        assets[asset_fp] = ctx
    else:
        assets.pop(asset_fp, None)
    out['assets'] = assets
    return normalize_root(out)


def resolve(root, asset_fp) -> Dict[str, str]:
    """Effective context for an asset: the per-asset override layered over the
    project default (override wins field-by-field). ``{}`` if neither is set."""
    root = normalize_root(root)
    eff = dict(root.get('default') or {})
    eff.update((root.get('assets') or {}).get(asset_fp) or {})
    return eff


# ── criticality contribution (consumed by intelligence.asset_criticality) ─────

def business_weight(ctx) -> int:
    """Total additive criticality bonus for a resolved context (0 if undeclared)."""
    ctx = normalize_context(ctx)
    return (_CRITICALITY_WEIGHT.get(ctx.get('criticality'), 0)
            + _SENSITIVITY_WEIGHT.get(ctx.get('data_sensitivity'), 0))


def business_factors(ctx) -> List[Dict]:
    """Named, auditable criticality factors for a resolved context (like the other
    ``asset_criticality`` factors). Empty when nothing is declared / weight is 0."""
    ctx = normalize_context(ctx)
    out: List[Dict] = []
    crit = ctx.get('criticality')
    if crit and _CRITICALITY_WEIGHT.get(crit):
        out.append({'factor': f'Бизнес-критичность: {CRITICALITY_LABELS[crit]}',
                    'points': _CRITICALITY_WEIGHT[crit]})
    sens = ctx.get('data_sensitivity')
    if sens and _SENSITIVITY_WEIGHT.get(sens):
        out.append({'factor': f'Чувствительность данных: {SENSITIVITY_LABELS[sens]}',
                    'points': _SENSITIVITY_WEIGHT[sens]})
    return out


def describe(ctx) -> str:
    """Compact one-line label for a resolved context (report card / CLI)."""
    ctx = normalize_context(ctx)
    parts = []
    if ctx.get('criticality'):
        parts.append(CRITICALITY_LABELS[ctx['criticality']])
    if ctx.get('data_sensitivity'):
        parts.append(SENSITIVITY_LABELS[ctx['data_sensitivity']])
    return ' · '.join(parts)


# ── management helpers (thin, for CLI / web — like core.scope_management) ──────

def show_business_context(store, target, *, create: bool = False) -> Dict:
    """Resolve a project and return ``{slug, url, business_context}``."""
    project = store.resolve(target, create=create)
    return {'slug': project.slug,
            'url': project.load_metadata().get('url') or project.url,
            'business_context': project.get_business_context()}


def set_business_context(store, target, *, create: bool = True,
                         asset_fp: Optional[str] = None,
                         criticality=None, data_sensitivity=None) -> Dict:
    """Set the default (or a per-asset, when ``asset_fp`` is given) context.

    Replace semantics, mirroring ``scope_management.set_scope``: the provided
    fields become the target context (omit a field to leave it unset). Pass both
    fields empty to clear that target."""
    project = store.resolve(target, create=create)
    ctx: Dict[str, str] = {}
    if criticality is not None:
        ctx['criticality'] = criticality
    if data_sensitivity is not None:
        ctx['data_sensitivity'] = data_sensitivity
    root = project.get_business_context()
    root = (set_asset(root, asset_fp, ctx) if asset_fp
            else set_default(root, ctx))
    project.set_business_context(root)
    return show_business_context(store, project.slug)


def clear_business_context(store, target, *, asset_fp: Optional[str] = None) -> Dict:
    """Clear one asset override (``asset_fp``) or the whole business context."""
    project = store.resolve(target, create=False)
    if asset_fp:
        project.set_business_context(
            set_asset(project.get_business_context(), asset_fp, {}))
    else:
        project.set_business_context(None)
    return show_business_context(store, project.slug)
