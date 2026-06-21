"""core/portfolio.py
Cross-project executive aggregates for the Executive Dashboard (F5, T5.1).

The portfolio view answers "how does my whole estate look right now?" by folding
together data that already exists — never recomputing it (architectural
invariant I3):

  * each project's ``metadata.json`` (via ``ProjectStore.list_projects`` /
    ``Project.scans``) — latest risk / attack-surface / secrets / high / medium,
    and the risk delta from the previous scan;
  * the F1 findings store — count of *active* (un-triaged-away) findings.

Split for testability (I5): the aggregators (``build_portfolio``,
``build_exposure_matrix``) are pure functions over already-loaded data;
``load_portfolio`` is the thin disk/DB loader. Offline, read-only — call the
loader from a worker thread (I4).
"""

from typing import Dict, List, Optional

from core.executive_summary import RISK_COLORS, RISK_ORDER
from core.trends import risk_direction

# Severity ramp (none → critical) for the exposure heatmap cells. Mid/dark tones
# so white cell text stays legible (see dashboard_charts.heatmap).
_HEAT_PALETTE = ['#2e7d32', '#9e9d24', '#f9a825', '#ef6c00', '#c62828']
# Worst-to-best so an unknown level sorts last.
_RISK_RANK = {level: i for i, level in enumerate(RISK_ORDER)}


def _num(value) -> Optional[float]:
    """Coerce to float, or ``None`` if missing/unparseable (preserves 'unknown'
    so a never-scanned metric is not shown as a real 0)."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int0(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _warning_summary(value) -> List[Dict]:
    return [w for w in (value or []) if isinstance(w, dict)]


def _warning_stages(summary: List[Dict]) -> str:
    stages = []
    for item in summary:
        stage = str(item.get('stage') or 'pipeline')
        if stage not in stages:
            stages.append(stage)
    return ', '.join(stages[:3])


def build_portfolio(projects_meta: List[Dict],
                    active_findings: Optional[Dict[str, int]] = None) -> Dict:
    """Fold per-project metadata into an executive portfolio (pure).

    ``projects_meta`` is the list of ``metadata.json`` dicts (newest-updated
    first) from ``ProjectStore.list_projects``. ``active_findings`` maps a
    project slug to its active-findings count (from ``FindingsStore.summary``);
    missing slugs count as 0. Returns ``{rows, totals}`` where each row is a
    display-ready per-project snapshot and ``totals`` is the estate roll-up.
    """
    active_findings = active_findings or {}
    rows: List[Dict] = []
    for meta in projects_meta or []:
        if not isinstance(meta, dict):
            continue
        slug = meta.get('slug') or '?'
        latest = meta.get('latest_scan') or {}
        scans = [s for s in meta.get('scans', []) if isinstance(s, dict)]

        # Risk delta vs the previous scan (None until there are two scans with a
        # numeric risk_score — never fabricate a baseline of 0).
        risk_delta = None
        cur = _num(latest.get('risk_score'))
        warning_summary = _warning_summary(latest.get('warning_summary'))
        if len(scans) >= 2:
            prev = _num(scans[-2].get('risk_score'))
            if cur is not None and prev is not None:
                risk_delta = cur - prev

        rows.append({
            'slug': slug,
            'url': meta.get('url') or '',
            'risk_level': latest.get('risk_level'),
            'risk_score': latest.get('risk_score'),
            'attack_surface': latest.get('attack_surface_score'),
            'secrets': _int0(latest.get('secrets')),
            'high': _int0(latest.get('high')),
            'medium': _int0(latest.get('medium')),
            # Detection-category breakdown (F5). Persisted on the scan entry by
            # Project._scan_entry; absent on pre-F5 metadata → 0 (clean cell).
            'source_map_leaks': _int0(latest.get('source_map_leaks')),
            'weak_cookies': _int0(latest.get('weak_cookies')),
            'graphql': _int0(latest.get('graphql')),
            'graphql_introspection': _int0(latest.get('graphql_introspection')),
            'warning_count': _int0(latest.get('warning_count')),
            'warning_summary': warning_summary,
            'warning_stages': _warning_stages(warning_summary),
            'active_findings': _int0(active_findings.get(slug)),
            'scan_count': _int0(meta.get('scan_count')),
            'updated_at': meta.get('updated_at') or '',
            'risk_delta': risk_delta,
            # Overall risk-trend direction across the whole history (up/down/flat) —
            # the companion to risk_delta (latest vs prev). Reuses the loaded scans
            # (EPIC 4); 'flat' until there are two numeric risk points.
            'risk_trend': risk_direction(scans),
        })

    # Worst risk first (executive triage), then most recently updated.
    rows.sort(key=lambda r: (_num(r['risk_score']) or 0.0,
                             r.get('updated_at') or ''),
              reverse=True)

    worst_level = None
    for r in rows:
        lvl = r.get('risk_level')
        if lvl in _RISK_RANK and (worst_level is None
                                  or _RISK_RANK[lvl] < _RISK_RANK[worst_level]):
            worst_level = lvl

    totals = {
        'projects': len(rows),
        'worst_risk_level': worst_level,
        'worst_risk_color': RISK_COLORS.get(worst_level, '#888'),
        'secrets': sum(r['secrets'] for r in rows),
        'high': sum(r['high'] for r in rows),
        'medium': sum(r['medium'] for r in rows),
        'warning_count': sum(r['warning_count'] for r in rows),
        'active_findings': sum(r['active_findings'] for r in rows),
    }
    return {'rows': rows, 'totals': totals}


# Per-column severity mapping for the exposure heatmap. Each level-fn takes the
# whole portfolio row and returns an index into _HEAT_PALETTE (0 = none/clean) —
# the row (not a single value) so detection columns can fold in a second signal
# (e.g. GraphQL introspection on top of the endpoint count).
def _level_secrets(r: Dict) -> int:
    return 4 if _int0(r.get('secrets')) > 0 else 0     # any leaked key is critical


def _level_high(r: Dict) -> int:
    v = _int0(r.get('high'))
    return 0 if v == 0 else (3 if v < 3 else 4)


def _level_medium(r: Dict) -> int:
    v = _int0(r.get('medium'))
    return 0 if v == 0 else (2 if v < 5 else 3)


def _level_active(r: Dict) -> int:
    v = _int0(r.get('active_findings'))
    if v == 0:
        return 0
    if v < 5:
        return 2
    if v < 10:
        return 3
    return 4


def _level_surface(r: Dict) -> int:
    from core.attack_surface import score_band
    return {'Minimal': 0, 'Low': 1, 'Medium': 2,
            'High': 3, 'Critical': 4}.get(score_band(_int0(r.get('attack_surface'))), 0)


def _level_sourcemap(r: Dict) -> int:
    # A source map exposing original source weighs like a leaked secret.
    v = _int0(r.get('source_map_leaks'))
    return 0 if v == 0 else (3 if v < 2 else 4)


def _level_cookie(r: Dict) -> int:
    v = _int0(r.get('weak_cookies'))
    return 0 if v == 0 else (2 if v < 3 else 3)


def _level_graphql(r: Dict) -> int:
    # Open introspection (full schema leak) is critical; a merely reachable
    # GraphQL API is moderate added surface; none is clean.
    if _int0(r.get('graphql_introspection')) > 0:
        return 4
    return 2 if _int0(r.get('graphql')) > 0 else 0


# (column label, cell-value row-key, level-fn(row)). One source of truth for the
# heatmap shape. Detection-category columns (SourceMap/Cookie/GraphQL) sit next
# to Secrets — together they break the exposure down by detection engine (F5).
_EXPOSURE_COLUMNS = [
    ('Secrets',     'secrets',         _level_secrets),
    ('SourceMap',   'source_map_leaks', _level_sourcemap),
    ('Cookie',      'weak_cookies',    _level_cookie),
    ('GraphQL',     'graphql',         _level_graphql),
    ('High',        'high',            _level_high),
    ('Medium',      'medium',          _level_medium),
    ('Surface',     'attack_surface',  _level_surface),
    ('Findings',    'active_findings', _level_active),
]


def build_exposure_matrix(rows: List[Dict]) -> Dict:
    """Build a project×exposure-category heatmap from portfolio ``rows`` (pure).

    Returns ``{row_labels, col_labels, cells}`` ready for
    ``dashboard_charts.heatmap`` — ``cells[r][c]`` is ``(display_text, colour)``,
    the colour chosen per-column from a severity ramp. Reuses the numbers already
    on each portfolio row; no extra I/O.
    """
    col_labels = [label for label, _, _ in _EXPOSURE_COLUMNS]
    row_labels: List[str] = []
    cells: List[List] = []
    for r in rows or []:
        row_labels.append(r.get('slug') or '?')
        line = []
        for _, key, level_fn in _EXPOSURE_COLUMNS:
            value = _int0(r.get(key))
            line.append((str(value), _HEAT_PALETTE[level_fn(r)]))
        cells.append(line)
    return {'row_labels': row_labels, 'col_labels': col_labels, 'cells': cells}


def active_findings_map() -> Dict[str, int]:
    """Map project slug → active-findings count from the F1 store (guarded).

    Shared by the portfolio and the company roll-up loaders so both read the
    same source. Best-effort: any store failure yields an empty map so the
    dashboards still render without findings."""
    active: Dict[str, int] = {}
    try:
        from core.findings_store import FindingsStore
        store = FindingsStore()
        for p in store.projects():
            slug = p.get('project')
            if slug:
                active[slug] = _int0(p.get('active'))
    except Exception:   # noqa: BLE001 — findings are best-effort for the dashboard
        active = {}
    return active


def load_portfolio(base: str) -> Dict:
    """Load the full portfolio for the projects tree under ``base`` (thin loader).

    Reads each project's metadata via ``ProjectStore`` and the active-findings
    count via the F1 store (guarded — the portfolio must render even if findings
    are unavailable), then delegates to the pure aggregator. Offline, read-only;
    run it off the GUI thread (I4).
    """
    from core.project import ProjectStore

    projects_meta = ProjectStore(base).list_projects()
    return build_portfolio(projects_meta, active_findings_map())
