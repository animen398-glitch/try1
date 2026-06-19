"""core/report_export.py
Offline CSV export of ASM data (findings triage list + project portfolio).

Pure stdlib (``csv`` + ``io``) — no dependency and no I/O of its own
(architectural invariants I1/I5): each function turns already-loaded rows into a
CSV *string*, and the GUI writes it to the file the user picks. PDF export is
deliberately not here — the self-contained ``report.html`` already prints to PDF
from the browser, so no heavy PDF dependency is bundled into the ``.exe``.
"""

import csv
import io
from typing import Dict, List, Optional, Sequence, Tuple

# (row key, CSV header) — explicit so column order/names are stable for export.
_FINDINGS_COLUMNS: Sequence[Tuple[str, str]] = (
    ('project', 'Project'), ('severity', 'Severity'), ('status', 'Status'),
    ('category', 'Category'), ('title', 'Title'), ('rule_id', 'Rule'),
    ('description', 'Description'), ('impact', 'Impact'),
    ('remediation', 'Remediation'),
    ('first_seen_at', 'First seen'), ('last_seen_at', 'Last seen'), ('id', 'ID'),
)

_PORTFOLIO_COLUMNS: Sequence[Tuple[str, str]] = (
    ('slug', 'Project'), ('url', 'URL'), ('risk_level', 'Risk'),
    ('risk_score', 'Score'), ('risk_delta', 'Delta'),
    ('attack_surface', 'Attack Surface'), ('secrets', 'Secrets'),
    ('high', 'High'), ('medium', 'Medium'),
    ('active_findings', 'Active Findings'), ('scan_count', 'Scans'),
    ('updated_at', 'Updated'),
)


_ASSETS_COLUMNS: Sequence[Tuple[str, str]] = (
    ('project', 'Project'), ('type', 'Type'), ('value', 'Value'),
    ('label', 'Label'), ('status', 'Status'),
    ('first_seen_at', 'First seen'), ('last_seen_at', 'Last seen'), ('id', 'ID'),
)


_TIMELINE_COLUMNS: Sequence[Tuple[str, str]] = (
    ('at', 'When'), ('scan_id', 'Scan'), ('severity', 'Severity'),
    ('section', 'Section'), ('type', 'Event'), ('title', 'Detail'),
)

_HISTORY_COLUMNS: Sequence[Tuple[str, str]] = (
    ('at', 'When'), ('scan_id', 'Scan'), ('risk_level', 'Risk'),
    ('risk_score', 'Risk Score'), ('attack_surface', 'Attack Surface'),
    ('secrets', 'Secrets'), ('high', 'High'), ('medium', 'Medium'),
)

_INTELLIGENCE_COLUMNS: Sequence[Tuple[str, str]] = (
    ('priority', 'Priority'), ('confidence', 'Confidence'),
    ('confidence_band', 'Confidence Band'), ('severity', 'Severity'),
    ('category', 'Category'), ('title', 'Title'),
    ('description', 'Description'), ('impact', 'Impact'),
    ('remediation', 'Remediation'), ('id', 'ID'),
)

_CRITICALITY_COLUMNS: Sequence[Tuple[str, str]] = (
    ('criticality', 'Criticality'), ('band', 'Band'), ('type', 'Type'),
    ('value', 'Value'), ('factors', 'Factors'), ('id', 'ID'),
)

_ATTACK_PATHS_COLUMNS: Sequence[Tuple[str, str]] = (
    ('score', 'Score'), ('band', 'Band'), ('entry', 'Entry'),
    ('entry_severity', 'Entry Severity'), ('pivot_type', 'Pivot Type'),
    ('pivot_node', 'Pivot Node'), ('size', 'Cluster Size'),
    ('targets', 'Targets'), ('critical_targets', 'Critical Targets'),
)

_ACCURACY_COLUMNS: Sequence[Tuple[str, str]] = (
    ('score', 'Confidence'), ('band', 'Band'), ('entity_type', 'Type'),
    ('label', 'Entity'), ('verification', 'Verification'),
    ('source', 'Source'), ('evidence', 'Evidence'),
)


def _fmt(value) -> str:
    """CSV cell text: ``None`` → '', everything else stringified."""
    return '' if value is None else str(value)


def _rows_to_csv(rows: Optional[List[Dict]],
                 columns: Sequence[Tuple[str, str]]) -> str:
    """Header + one line per dict row, in ``columns`` order. ``csv`` handles
    quoting of commas/quotes/newlines, so the output is always well-formed."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([header for _, header in columns])
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        writer.writerow([_fmt(row.get(key)) for key, _ in columns])
    return buf.getvalue()


def findings_csv(findings: Optional[List[Dict]]) -> str:
    """CSV of a findings list (``FindingsStore.list_findings`` rows).

    Each row is enriched with description/impact/remediation from the
    finding_knowledge catalog (F-O3) so the export carries the full finding
    object, DefectDojo-style."""
    from core.finding_knowledge import annotate
    return _rows_to_csv(annotate(list(findings or [])), _FINDINGS_COLUMNS)


def assets_csv(assets: Optional[List[Dict]]) -> str:
    """CSV of an assets list (``AssetStore.list_assets`` rows)."""
    return _rows_to_csv(assets, _ASSETS_COLUMNS)


def timeline_csv(events: Optional[List[Dict]]) -> str:
    """CSV of a project's change-feed events (``timeline.build_timeline`` 'events').

    Each event is ``{at, scan_id, type, title, severity, section}`` — the same rows
    the GUI Timeline tab and the web /timeline endpoint show."""
    return _rows_to_csv(events, _TIMELINE_COLUMNS)


def history_csv(series: Optional[List[Dict]]) -> str:
    """CSV of a project's per-scan risk history (``timeline.build_series`` points).

    The metric-series counterpart of ``timeline_csv`` (which exports change events):
    one row per scan with the risk/attack-surface/secrets/high/medium numbers, for
    trend analysis outside the app (EPIC 4)."""
    return _rows_to_csv(series, _HISTORY_COLUMNS)


def intelligence_csv(items: Optional[List[Dict]]) -> str:
    """CSV of priority-ranked findings (``intelligence.build_intelligence`` items).

    Each item carries a nested ``explanation`` (description/impact/remediation from
    the finding_knowledge catalog); it is flattened into top-level columns so the
    export is a single flat table, in the same priority order as the GUI tab."""
    flat: List[Dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        info = it.get('explanation') or {}
        flat.append({**it,
                     'description': info.get('description'),
                     'impact': info.get('impact'),
                     'remediation': info.get('remediation')})
    return _rows_to_csv(flat, _INTELLIGENCE_COLUMNS)


def criticality_csv(items: Optional[List[Dict]]) -> str:
    """CSV of assets ranked by criticality (``intelligence.build_asset_criticality``
    items). The nested ``factors`` list (each ``{factor, points}``) is flattened to
    a single readable cell so the export stays a flat table, in criticality order."""
    flat: List[Dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        factors = '; '.join(
            f"{f.get('factor', '')} (+{f.get('points', 0)})"
            for f in (it.get('factors') or []) if isinstance(f, dict))
        flat.append({**it, 'factors': factors})
    return _rows_to_csv(flat, _CRITICALITY_COLUMNS)


def attack_paths_csv(paths: Optional[List[Dict]]) -> str:
    """CSV of lateral attack paths (``intelligence.build_attack_paths`` paths).

    The ``targets`` host list is flattened to a single cell so the export stays a
    flat table, in score order (same as the GUI tab and the web /attack-paths view)."""
    flat: List[Dict] = []
    for p in paths or []:
        if not isinstance(p, dict):
            continue
        flat.append({**p, 'targets': '; '.join(str(t) for t in (p.get('targets') or []))})
    return _rows_to_csv(flat, _ATTACK_PATHS_COLUMNS)


def accuracy_csv(items: Optional[List[Dict]]) -> str:
    """CSV of scan-accuracy entities (``intelligence.build_accuracy`` items).

    The ``source`` and ``evidence`` lists are flattened to single cells so the
    export stays a flat table, in confidence order (same as the GUI tab and the
    web /accuracy view)."""
    flat: List[Dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        flat.append({**it,
                     'source': '; '.join(str(s) for s in (it.get('source') or [])),
                     'evidence': '; '.join(str(e) for e in (it.get('evidence') or []))})
    return _rows_to_csv(flat, _ACCURACY_COLUMNS)


def portfolio_csv(portfolio) -> str:
    """CSV of the project portfolio. Accepts either the full
    ``portfolio.load_portfolio`` dict (``{'rows': [...]}``) or a bare row list."""
    rows = portfolio.get('rows') if isinstance(portfolio, dict) else portfolio
    return _rows_to_csv(rows, _PORTFOLIO_COLUMNS)
