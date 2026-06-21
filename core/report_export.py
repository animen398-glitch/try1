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
import json
from typing import Dict, List, Optional, Sequence, Tuple

# (row key, CSV header) — explicit so column order/names are stable for export.
_FINDINGS_COLUMNS: Sequence[Tuple[str, str]] = (
    ('project', 'Project'), ('severity', 'Severity'), ('status', 'Status'),
    ('category', 'Category'), ('title', 'Title'), ('rule_id', 'Rule'),
    ('description', 'Description'), ('impact', 'Impact'),
    ('remediation', 'Remediation'), ('evidence_artifacts', 'Evidence Artifacts'),
    ('first_seen_at', 'First seen'), ('last_seen_at', 'Last seen'), ('id', 'ID'),
)

_PORTFOLIO_COLUMNS: Sequence[Tuple[str, str]] = (
    ('slug', 'Project'), ('url', 'URL'), ('risk_level', 'Risk'),
    ('risk_score', 'Score'), ('risk_delta', 'Delta'),
    ('attack_surface', 'Attack Surface'), ('secrets', 'Secrets'),
    ('high', 'High'), ('medium', 'Medium'),
    ('warning_count', 'Warnings'), ('warning_stages', 'Warning Stages'),
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

_EXPOSURE_COLUMNS: Sequence[Tuple[str, str]] = (
    ('exposure', 'Exposure'), ('band', 'Band'), ('type', 'Type'),
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

_TECHNOLOGY_RISK_COLUMNS: Sequence[Tuple[str, str]] = (
    ('score', 'Score'), ('band', 'Band'), ('kind', 'Kind'),
    ('name', 'Name'), ('version', 'Version'), ('category', 'Category'),
    ('reason', 'Reason'), ('evidence', 'Evidence'),
)

_EVIDENCE_INTEGRITY_COLUMNS: Sequence[Tuple[str, str]] = (
    ('scan_id', 'Scan'), ('status', 'Status'), ('ok', 'OK'),
    ('checked', 'Checked'), ('missing_count', 'Missing'),
    ('changed_count', 'Changed'), ('warning', 'Warning'), ('scan_dir', 'Scan Dir'),
)

_OSINT_CATALOG_COLUMNS: Sequence[Tuple[str, str]] = (
    ('status', 'Status'), ('name', 'Workflow'), ('category', 'Category'),
    ('network', 'Network'), ('coverage', 'Coverage'), ('goal', 'Goal'),
    ('ran', 'Engines Ran'), ('missing', 'Engines Missing'),
    ('optional_ran', 'Optional Ran'), ('produces', 'Produces'),
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


def _evidence_artifacts(row: Dict) -> str:
    evidence = row.get('evidence') if isinstance(row, dict) else {}
    refs = evidence.get('evidence_refs') if isinstance(evidence, dict) else None
    if not isinstance(refs, list):
        return ''
    out = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        path = str(ref.get('path') or '').strip()
        if not path:
            continue
        phase = str(ref.get('phase') or '').strip()
        aid = str(ref.get('artifact_id') or '').strip()
        prefix = aid.split(':', 1)[-1][:12] if aid else ''
        label = f'{phase}:{path}' if phase else path
        out.append(f'{label}#{prefix}' if prefix else label)
    return '; '.join(out)


def findings_csv(findings: Optional[List[Dict]]) -> str:
    """CSV of a findings list (``FindingsStore.list_findings`` rows).

    Each row is enriched with description/impact/remediation from the
    finding_knowledge catalog (F-O3) so the export carries the full finding
    object, DefectDojo-style."""
    from core.finding_knowledge import annotate
    rows = []
    for row in annotate(list(findings or [])):
        rows.append({**row, 'evidence_artifacts': _evidence_artifacts(row)})
    return _rows_to_csv(rows, _FINDINGS_COLUMNS)


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


def exposure_csv(items: Optional[List[Dict]]) -> str:
    """CSV of assets ranked by exposure (``intelligence.build_exposure`` items). The
    nested ``factors`` list (each ``{factor, points}``) is flattened to a single
    readable cell so the export stays a flat table, in exposure order."""
    flat: List[Dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        factors = '; '.join(
            f"{f.get('factor', '')} (+{f.get('points', 0)})"
            for f in (it.get('factors') or []) if isinstance(f, dict))
        flat.append({**it, 'factors': factors})
    return _rows_to_csv(flat, _EXPOSURE_COLUMNS)


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


def technology_risk_csv(items: Optional[List[Dict]]) -> str:
    """CSV of technology-risk items (``tech_risk.build_technology_risk`` items).

    The ``evidence`` list is flattened to a single readable cell so the export stays a
    flat table, in score order (same as the report card and the web /technology-risk
    view)."""
    flat: List[Dict] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        flat.append({**it, 'evidence': '; '.join(str(e) for e in (it.get('evidence') or []))})
    return _rows_to_csv(flat, _TECHNOLOGY_RISK_COLUMNS)


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


def osint_catalog_csv(workflows: Optional[List[Dict]]) -> str:
    """CSV of OSINT-workflow coverage (``osint_catalog.assess`` rows).

    The engine/produces lists are flattened to single readable cells and a
    ``coverage`` ratio (ran/total required engines) is derived, so the export
    stays a flat table — the same rows the GUI OSINT Catalog tab shows."""
    flat: List[Dict] = []
    for wf in workflows or []:
        if not isinstance(wf, dict):
            continue
        engines = wf.get('engines') or []
        ran = wf.get('ran') or []
        flat.append({
            **wf,
            'coverage': f'{len(ran)}/{len(engines)}',
            'ran': '; '.join(str(e) for e in ran),
            'missing': '; '.join(str(e) for e in (wf.get('missing') or [])),
            'optional_ran': '; '.join(str(e) for e in (wf.get('optional_ran') or [])),
            'produces': '; '.join(str(p) for p in (wf.get('produces') or [])),
        })
    return _rows_to_csv(flat, _OSINT_CATALOG_COLUMNS)


def evidence_integrity_csv(audits) -> str:
    """CSV of ``core.evidence.audit_scan`` results for handoff/export.

    The helper is intentionally pure: callers decide which scans to audit and
    pass the resulting dicts here. Artifact contents are never exported.
    """
    from core.evidence import integrity_warning
    if isinstance(audits, dict):
        audits = [audits]
    rows: List[Dict] = []
    for audit in audits or []:
        if not isinstance(audit, dict):
            continue
        missing = audit.get('missing') if isinstance(audit.get('missing'), list) else []
        changed = audit.get('changed') if isinstance(audit.get('changed'), list) else []
        rows.append({
            **audit,
            'missing_count': len(missing),
            'changed_count': len(changed),
            'warning': integrity_warning(audit) or '',
        })
    return _rows_to_csv(rows, _EVIDENCE_INTEGRITY_COLUMNS)


def portfolio_csv(portfolio) -> str:
    """CSV of the project portfolio. Accepts either the full
    ``portfolio.load_portfolio`` dict (``{'rows': [...]}``) or a bare row list."""
    rows = portfolio.get('rows') if isinstance(portfolio, dict) else portfolio
    return _rows_to_csv(rows, _PORTFOLIO_COLUMNS)


# ── SARIF 2.1.0 (EPIC 16 F1) ────────────────────────────────────────────────────
# The standard static-analysis interchange format: GitHub code scanning, Azure
# DevOps and IDEs ingest it directly. Pure stdlib json, same purity invariant as
# the CSV exporters - turns already-loaded findings into a string, no I/O.

_SARIF_TOOL_NAME = 'Advanced Site Analyzer'
_SARIF_INFO_URI = 'https://github.com/animen398-glitch/try1'

# severity -> SARIF result level (error/warning/note is the SARIF vocabulary).
_SARIF_LEVEL = {'critical': 'error', 'high': 'error', 'medium': 'warning',
                'low': 'note', 'info': 'note'}
# GitHub code scanning ranks/ filters by the numeric security-severity (0-10)
# carried in rule properties.
_SARIF_SECURITY_SEVERITY = {'critical': '9.5', 'high': '8.0', 'medium': '5.0',
                            'low': '3.0', 'info': '1.0'}


def _sarif_rule_id(finding: Dict) -> str:
    """Stable rule identity for a finding: rule_id, else category, else generic."""
    return (str(finding.get('rule_id') or '').strip()
            or str(finding.get('category') or '').strip()
            or 'finding')


def _sarif_location(finding: Dict):
    """SARIF physicalLocation from evidence.location (URL/host), or None."""
    ev = finding.get('evidence') if isinstance(finding, dict) else None
    loc = str((ev.get('location') if isinstance(ev, dict) else '') or '').strip()
    if not loc:
        return None
    return {'physicalLocation': {'artifactLocation': {'uri': loc}}}


def _sarif_help(finding: Dict) -> str:
    """Rule help text: impact + remediation from the annotated finding object."""
    parts = []
    if finding.get('impact'):
        parts.append(f"Impact: {finding['impact']}")
    if finding.get('remediation'):
        parts.append(f"Remediation: {finding['remediation']}")
    return '\n\n'.join(parts)


def _sarif_tags(finding: Dict) -> List[str]:
    """Rule tags: the canonical category plus the CWE taxonomy and OWASP class the
    compliance mapping derives (one SSOT — ``core.compliance.classify``). CWEs use
    the ``external/cwe/cwe-NNN`` convention GitHub code scanning recognizes for
    filtering/grouping, so the SARIF carries the same taxonomy the compliance report
    shows."""
    from core.compliance import classify
    cat = str(finding.get('category') or '').strip()
    cls = classify(cat, finding.get('rule_id', ''), finding.get('title', ''))
    tags = [t for t in [cat] if t]
    # The producer's explicit per-finding CWE (e.g. NVD's authoritative weakness for
    # a CVE) is more precise than the category default — surface both, de-duplicated.
    ev = finding.get('evidence') if isinstance(finding.get('evidence'), dict) else {}
    explicit = ev.get('cwe') if isinstance(ev.get('cwe'), list) else []
    for cwe in list(explicit) + list(cls.get('cwe') or []):
        num = str(cwe).lower().replace('cwe-', '').strip()
        tag = f'external/cwe/cwe-{num}'
        if num and tag not in tags:
            tags.append(tag)
    if cls.get('owasp'):
        tags.append(f"OWASP:{cls['owasp']}")
    return tags


def findings_sarif(findings: Optional[List[Dict]], *,
                   tool_version: str = '') -> str:
    """SARIF 2.1.0 JSON for a findings list (``FindingsStore`` rows).

    Each finding becomes a SARIF result; distinct (category/rule_id) pairs become
    reportingDescriptors (rules) with description/impact/remediation pulled from the
    finding_knowledge catalog (same enrichment as ``findings_csv``). ``severity``
    maps to the SARIF level + the numeric security-severity GitHub reads; the rule
    tags carry the CWE taxonomy (``external/cwe/cwe-NNN``) and OWASP class from the
    compliance SSOT; ``evidence.location`` is emitted as the result's
    physicalLocation URI when present. Pure stdlib json; an empty list yields a
    valid empty run."""
    from core.finding_knowledge import annotate
    rows = annotate(list(findings or []))

    rules: Dict[str, Dict] = {}
    results: List[Dict] = []
    for f in rows:
        rid = _sarif_rule_id(f)
        sev = str(f.get('severity') or 'info').lower()
        level = _SARIF_LEVEL.get(sev, 'note')
        if rid not in rules:
            rules[rid] = {
                'id': rid,
                'name': rid,
                'shortDescription': {'text': str(f.get('category') or rid)},
                'fullDescription': {'text': str(f.get('description') or '')},
                'help': {'text': _sarif_help(f)},
                'defaultConfiguration': {'level': level},
                'properties': {
                    'tags': _sarif_tags(f),
                    'security-severity': _SARIF_SECURITY_SEVERITY.get(sev, '1.0'),
                },
            }
        result = {
            'ruleId': rid,
            'level': level,
            'message': {'text': str(f.get('title') or rid)},
            'properties': {
                'severity': sev,
                'status': str(f.get('status') or ''),
                'firstSeen': str(f.get('first_seen_at') or ''),
            },
        }
        loc = _sarif_location(f)
        if loc:
            result['locations'] = [loc]
        results.append(result)

    doc = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': _SARIF_TOOL_NAME,
                'version': str(tool_version or '0.0.0'),
                'informationUri': _SARIF_INFO_URI,
                'rules': list(rules.values()),
            }},
            'results': results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ── Markdown report (EPIC 16 F2) ────────────────────────────────────────────────
# A client/GitHub-friendly text deliverable rendered from the same scan report dict
# that feeds report.html — for issues, wikis, email and PRs. Pure stdlib.

def report_markdown(report: Optional[Dict]) -> str:
    """Markdown deliverable from a scan ``report`` dict (pure, offline).

    Renders the executive summary already in ``report['executive_summary']``
    (verdict + headline chips + key findings + score breakdown + recommendations)
    with ``report['summary']`` kept as a legacy fallback. Empty/old reports
    degrade to a minimal header rather than raising."""
    report = report if isinstance(report, dict) else {}
    summary = report.get('executive_summary')
    if not isinstance(summary, dict):
        summary = report.get('summary') if isinstance(report.get('summary'), dict) else {}

    target = report.get('domain') or report.get('url') or 'target'
    out: List[str] = [f'# Security Report — {target}', '']

    started, finished = report.get('started_at') or '', report.get('finished_at') or ''
    if started or finished:
        out.append(f'_Scan: {started} → {finished}_')
        out.append('')

    level = summary.get('risk_level', 'Clean')
    score = summary.get('risk_100', summary.get('risk_score', 0))
    out.append(f'## Risk verdict: **{level}** ({score}/100)')
    out.append('')

    try:
        from core.executive_summary import headline
        chips = (headline(summary) or {}).get('chips') or []
    except Exception:  # noqa: BLE001 — headline is best-effort decoration
        chips = []
    if chips:
        out.append('**Highlights:** ' + ' · '.join(
            f"`{c.get('label', '')}`" for c in chips if isinstance(c, dict)))
        out.append('')

    def _section(title: str, items, fmt) -> None:
        rows = [fmt(it) for it in (items or []) if it]
        rows = [r for r in rows if r]
        if rows:
            out.append(f'## {title}')
            out.extend(f'- {r}' for r in rows)
            out.append('')

    _section('Key findings', summary.get('key_findings'), lambda k: str(k))
    _section('Из чего риск (score breakdown)', summary.get('risk_factors'),
             lambda f: (f"{f.get('factor', '')}: +{f.get('points', 0)}"
                        f"{(' — ' + str(f.get('detail'))) if f.get('detail') else ''}"
                        if isinstance(f, dict) else str(f)))
    _section('Recommendations', summary.get('recommendations'), lambda r: str(r))
    _section('Warnings', report.get('warnings'),
             lambda w: (
                 f"{w.get('stage', 'pipeline')}: "
                 f"{w.get('message') or w.get('error') or 'warning'}"
                 f"{(' — ' + str(w.get('error'))) if w.get('error') else ''}"
                 if isinstance(w, dict) else str(w)
             ))

    return '\n'.join(out).rstrip() + '\n'


# ── OWASP/CWE compliance report (EPIC 16 wave 2, A3) ────────────────────────────
# A compliance deliverable: the active findings rolled up against the OWASP Top 10
# 2021 (+ CWE), showing both coverage and the clean categories. Pure stdlib.

def _severities_cell(sev: Dict[str, int]) -> str:
    """'2 high, 1 medium' from a severity-count dict (worst first), or '—'."""
    order = ('critical', 'high', 'medium', 'low', 'info')
    parts = [f'{sev[s]} {s}' for s in order if sev.get(s)]
    return ', '.join(parts) if parts else '—'


def compliance_markdown(findings: Optional[List[Dict]]) -> str:
    """OWASP Top 10 (2021) + CWE compliance report from a findings list (pure).

    Renders the ``core.compliance.build_compliance`` roll-up as a portable Markdown
    table — every Top-10 category (clean ones marked OK), the mapped CWEs, finding
    counts and severities, plus an Unmapped section for unrecognized vuln subtypes.
    An empty list yields a valid all-clean report."""
    from core.compliance import build_compliance
    data = build_compliance(findings)
    s = data['summary']

    out: List[str] = ['# OWASP Top 10 (2021) Compliance Report', '']
    out.append(f"_Active findings: {s['total_findings']} · categories with "
               f"findings: {s['categories_with_findings']}/10"
               + (f" · unmapped: {s['unmapped']}" if s['unmapped'] else '') + '_')
    out.append('')
    out.append('| OWASP category | Status | CWE | Findings | Severities |')
    out.append('|---|---|---|---|---|')
    for b in data['by_owasp']:
        status = '⚠️ findings' if b['count'] else '✅ OK'
        cwe = ', '.join(b['cwe']) if b['cwe'] else '—'
        out.append(f"| {b['id']} {b['name']} | {status} | {cwe} | "
                   f"{b['count']} | {_severities_cell(b['severities'])} |")
    out.append('')

    for b in data['by_owasp']:
        if not b['count']:
            continue
        out.append(f"## {b['id']} {b['name']} ({b['count']})")
        for f in b['findings']:
            cwe = f" ({', '.join(f['cwe'])})" if f['cwe'] else ''
            out.append(f"- [{f['severity']}] {f['title']}{cwe}")
        out.append('')

    if data['unmapped']:
        out.append('## Unmapped (review)')
        out.append('_Findings without a confident OWASP class — review manually._')
        for f in data['unmapped']:
            out.append(f"- [{f['severity']}] {f['title']} "
                       f"({f['category'] or 'unknown'})")
        out.append('')

    return '\n'.join(out).rstrip() + '\n'
