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


def portfolio_csv(portfolio) -> str:
    """CSV of the project portfolio. Accepts either the full
    ``portfolio.load_portfolio`` dict (``{'rows': [...]}``) or a bare row list."""
    rows = portfolio.get('rows') if isinstance(portfolio, dict) else portfolio
    return _rows_to_csv(rows, _PORTFOLIO_COLUMNS)
