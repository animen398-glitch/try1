"""core/vuln_report.py
Render and export a standalone vulnerability report (HTML + JSON) from the
findings produced by VulnScanner. render_html() is pure and unit-tested;
export() writes both formats next to a chosen path.
"""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core.report_charts import stacked_bar
from core.vuln_scanner import (
    SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM, VulnScanner,
)

try:
    import fpdf  # noqa: F401  (optional — enables PDF export)
    _HAS_FPDF = True
except ImportError:
    _HAS_FPDF = False

# Map characters the PDF core fonts (latin-1) can't render to ASCII.
_PDF_REPL = {
    '—': '-', '–': '-', '→': '->', '≈': '~',
    '…': '...', '‘': "'", '’': "'", '“': '"',
    '”': '"', '•': '*',
}

_SEVERITY_ORDER = [SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_INFO]
_SEVERITY_COLOR = {
    SEVERITY_HIGH: '#c62828',
    SEVERITY_MEDIUM: '#f9a825',
    SEVERITY_INFO: '#2e7d32',
}


def render_html(target: str, findings: List[Dict],
                summary: Optional[Dict] = None) -> str:
    """Return a self-contained HTML vulnerability report."""
    e = html.escape
    summary = summary or VulnScanner.summarize(findings)
    generated = datetime.now().isoformat(timespec='seconds')

    sections = []
    for sev in _SEVERITY_ORDER:
        group = [f for f in findings if f.get('severity') == sev]
        if not group:
            continue
        colour = _SEVERITY_COLOR[sev]
        items = []
        for f in group:
            detail = f.get('detail', '')
            detail_html = (f'<div style="color:#555;font-size:12px;margin-top:2px;">'
                           f'{e(str(detail))}</div>') if detail else ''
            items.append(
                f'<li style="margin:8px 0;padding-left:8px;'
                f'border-left:3px solid {colour};">'
                f'<b>{e(str(f.get("title", "")))}</b>{detail_html}</li>'
            )
        sections.append(
            f'<section style="margin:16px 0;">'
            f'<h2 style="font-size:15px;color:{colour};margin:0 0 6px;">'
            f'{e(sev)} ({len(group)})</h2>'
            f'<ul style="list-style:none;padding:0;margin:0;">{"".join(items)}</ul>'
            f'</section>'
        )

    if not sections:
        sections.append('<p style="color:#2e7d32;">No findings — looks clean.</p>')

    badge = (
        f'<span style="color:{_SEVERITY_COLOR[SEVERITY_HIGH]};">'
        f'High: {summary.get("high", 0)}</span> · '
        f'<span style="color:{_SEVERITY_COLOR[SEVERITY_MEDIUM]};">'
        f'Medium: {summary.get("medium", 0)}</span> · '
        f'<span style="color:{_SEVERITY_COLOR[SEVERITY_INFO]};">'
        f'Info: {summary.get("info", 0)}</span> · '
        f'risk score: <b>{summary.get("risk_score", 0)}</b>'
    )

    # Offline visual severity distribution (inline-CSS bar, no JS/deps).
    sev_bar = stacked_bar([
        (SEVERITY_HIGH, summary.get('high', 0), _SEVERITY_COLOR[SEVERITY_HIGH]),
        (SEVERITY_MEDIUM, summary.get('medium', 0), _SEVERITY_COLOR[SEVERITY_MEDIUM]),
        (SEVERITY_INFO, summary.get('info', 0), _SEVERITY_COLOR[SEVERITY_INFO]),
    ], empty_note='No findings')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Vulnerability Report — {e(target)}</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;
max-width:820px;margin:24px auto;padding:0 16px;color:#222;">
<h1 style="font-size:21px;margin-bottom:4px;">Vulnerability Report</h1>
<p style="color:#666;font-size:13px;margin-top:0;">
  <b>{e(target)}</b><br>{badge}<br>Generated: {e(generated)}
</p>
<div style="margin:8px 0 16px;">{sev_bar}</div>
{''.join(sections)}
<p style="color:#aaa;font-size:11px;margin-top:24px;">
  Advanced Site Analyzer · VulnScanner
</p>
</body></html>"""


def _pdf_safe(text) -> str:
    s = str(text)
    for bad, good in _PDF_REPL.items():
        s = s.replace(bad, good)
    return s.encode('latin-1', 'replace').decode('latin-1')


def export_pdf(path, target: str, findings: List[Dict],
               summary: Optional[Dict] = None) -> Optional[str]:
    """Write a PDF vulnerability report; returns its path, or None if fpdf2
    is not installed."""
    if not _HAS_FPDF:
        return None
    from fpdf import FPDF

    summary = summary or VulnScanner.summarize(findings)
    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()

    def line(text, height=5):
        # new_x/new_y keep the cursor at the left margin on the next row,
        # otherwise fpdf2 leaves x at the right margin → zero-width cells.
        pdf.multi_cell(0, height, _pdf_safe(text),
                       new_x='LMARGIN', new_y='NEXT')

    pdf.set_font('Helvetica', 'B', 16)
    line('Vulnerability Report', 9)
    pdf.set_font('Helvetica', '', 10)
    line(target, 6)
    line(f"High {summary.get('high', 0)} / Medium {summary.get('medium', 0)} / "
         f"Info {summary.get('info', 0)} - risk score {summary.get('risk_score', 0)}", 6)
    pdf.ln(3)

    for sev in _SEVERITY_ORDER:
        group = [f for f in findings if f.get('severity') == sev]
        if not group:
            continue
        pdf.set_font('Helvetica', 'B', 12)
        line(f'{sev} ({len(group)})', 8)
        pdf.set_font('Helvetica', '', 10)
        for f in group:
            line(f"- {f.get('title', '')}")
            if f.get('detail'):
                pdf.set_text_color(110, 110, 110)
                line(f"    {f['detail']}")
                pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    pdf.output(str(path))
    return str(path)


def export(path: str, target: str, findings: List[Dict],
           summary: Optional[Dict] = None) -> Dict[str, str]:
    """Write <path>.html, .json (and .pdf if fpdf2 is available).

    Returns a dict of the written file paths keyed by format.
    """
    summary = summary or VulnScanner.summarize(findings)
    base = Path(path)
    if base.suffix.lower() in ('.html', '.json', '.pdf'):
        base = base.with_suffix('')
    base.parent.mkdir(parents=True, exist_ok=True)

    html_path = base.with_suffix('.html')
    json_path = base.with_suffix('.json')
    html_path.write_text(render_html(target, findings, summary), encoding='utf-8')
    json_path.write_text(
        json.dumps({'target': target, 'summary': summary, 'findings': findings},
                   indent=2, ensure_ascii=False, default=str),
        encoding='utf-8',
    )
    written = {'html': str(html_path), 'json': str(json_path)}

    pdf_path = export_pdf(base.with_suffix('.pdf'), target, findings, summary)
    if pdf_path:
        written['pdf'] = pdf_path
    return written
