"""core/threat_intel.py
KEV/EPSS threat orchestration — fetch+persist (network) and annotate (offline).

Sits between the raw feeds (:mod:`core.threat_feed`), the per-CVE cache
(:class:`core.cve_store.CVEStore`), and the findings. Two responsibilities:

  * :func:`enrich_cves` — the network step: for the CVEs that are stale/missing
    in the cache, fetch KEV once + EPSS for them, and persist per-CVE results.
  * :func:`annotate` — the derive-on-read step: read the cache only (no network)
    and attach a ``threat`` block to each CVE-bearing finding, deriving a
    deterministic ``tier`` (high/medium/None) that feeds the existing priority
    ``threat_tier`` input without changing the priority formula.

Pure of business logic beyond the agreed thresholds; no second data model — the
cache is :class:`CVEStore`, the finding ``threat`` block is derive-on-read.
"""

from typing import Callable, Dict, List, Optional

from core.findings_adapter import extract_cve
from core.threat_feed import DEFAULT_FRESH_SECONDS, fetch_epss, fetch_kev


# threat_tier thresholds (decision, 2026-06-28). KEV (exploited in the wild) is
# the strongest signal; EPSS percentile is normalized 0–1 and steadier than the
# raw score. Named so they can be tuned without touching the mapping logic.
EPSS_HIGH_PERCENTILE = 0.90
EPSS_MEDIUM_PERCENTILE = 0.50

_SOURCE = 'kev-epss'


def threat_tier_from(kev: bool, epss_percentile: Optional[float]) -> Optional[str]:
    """Deterministic exploitability tier: 'high' / 'medium' / None."""
    if kev:
        return 'high'
    if epss_percentile is None:
        return None
    if epss_percentile >= EPSS_HIGH_PERCENTILE:
        return 'high'
    if epss_percentile >= EPSS_MEDIUM_PERCENTILE:
        return 'medium'
    return None


def cve_of(finding: Dict) -> Optional[str]:
    """The CVE a finding refers to, also honoring a CVE-shaped ``rule_id``."""
    if not isinstance(finding, dict):
        return None
    probe = dict(finding)
    if not probe.get('cve'):
        probe['cve'] = finding.get('rule_id')
    return extract_cve(probe)


def cve_ids_from_findings(findings: List[Dict]) -> List[str]:
    """Sorted unique CVE ids referenced by the findings."""
    out = set()
    for f in findings or []:
        cve = cve_of(f)
        if cve:
            out.add(cve)
    return sorted(out)


def enrich_cves(cve_ids: List[str], *,
                store: Optional[object] = None,
                kev_get: Optional[Callable[[str], str]] = None,
                epss_get: Optional[Callable[[str], str]] = None,
                fresh_seconds: int = DEFAULT_FRESH_SECONDS) -> Dict[str, Dict]:
    """Fetch+persist KEV/EPSS for stale/missing CVEs; return per-CVE threat rows.

    Network is opt-in and soft-degrading: if the KEV catalog comes back empty
    (a real catalog is never empty → treat as a fetch failure) and EPSS is empty
    too, nothing is persisted and the existing cache is left intact."""
    active = store
    if active is None:
        from core.cve_store import CVEStore
        active = CVEStore()

    wanted = sorted({str(c).strip().upper() for c in (cve_ids or []) if str(c).strip()})
    stale: List[str] = []
    for cve in wanted:
        row = active.get_cve_threat(cve)
        if row is None or row.get('age', float('inf')) >= fresh_seconds:
            stale.append(cve)

    if stale:
        kev_catalog = fetch_kev(get=kev_get)
        epss_map = fetch_epss(stale, get=epss_get)
        # A non-empty KEV catalog means the fetch worked → membership is reliable.
        if kev_catalog or epss_map:
            for cve in stale:
                ep = epss_map.get(cve) or {}
                active.put_cve_threat(cve, {
                    'kev': cve in kev_catalog,
                    'kev_date': kev_catalog.get(cve),
                    'epss': ep.get('score'),
                    'epss_percentile': ep.get('percentile'),
                })

    out: Dict[str, Dict] = {}
    for cve in wanted:
        row = active.get_cve_threat(cve)
        if row is not None:
            out[cve] = row
    return out


def _threat_block(row: Dict) -> Dict:
    kev = bool(row.get('kev'))
    pct = row.get('epss_percentile')
    return {
        'kev': kev,
        'epss': row.get('epss'),
        'epss_percentile': pct,
        'tier': threat_tier_from(kev, pct),
        'source': _SOURCE,
    }


def annotate(findings: List[Dict], *, store: Optional[object] = None) -> List[Dict]:
    """Attach a ``threat`` block to CVE-bearing findings from the cache (offline).

    Returns new finding dicts (inputs untouched); a finding without a CVE or
    without a cached threat row is returned unchanged."""
    active = store
    if active is None:
        from core.cve_store import CVEStore
        active = CVEStore()

    out: List[Dict] = []
    for f in findings or []:
        if not isinstance(f, dict):
            out.append(f)
            continue
        cve = cve_of(f)
        row = active.get_cve_threat(cve) if cve else None
        if row is None:
            out.append(f)
            continue
        enriched = dict(f)
        enriched['threat'] = _threat_block(row)
        out.append(enriched)
    return out


def annotate_offline(findings: List[Dict], *,
                     store: Optional[object] = None) -> List[Dict]:
    """Best-effort offline annotate: like :func:`annotate` but never raises — a
    cold/missing cache or any error returns the findings unchanged.

    The single read-side wrapper used by the SLA / alerts / timeline / priority
    paths so each tightening site sees the ``threat`` block without
    re-implementing the same guard (a cold cache is a genuine no-op, so an
    un-enriched run is untouched)."""
    try:
        return annotate(findings, store=store)
    except Exception:   # noqa: BLE001 — threat context is best-effort
        return findings


def threat_label(threat: Optional[Dict]) -> str:
    """Short human label for a finding's exploitability ``threat`` block (the
    single wording source for GUI/console). ``''`` when there is no qualifying
    signal. KEV (exploited in the wild) is called out explicitly; EPSS shows the
    percentile so a high-probability non-KEV finding still reads clearly."""
    if not isinstance(threat, dict):
        return ''
    parts: List[str] = []
    if threat.get('kev'):
        parts.append('KEV — известно эксплуатируется')
    pct = threat.get('epss_percentile')
    if isinstance(pct, (int, float)):
        parts.append(f'EPSS {round(pct * 100)}%')
    return ' · '.join(parts)


def kev_events(findings: List[Dict]) -> List[Dict]:
    """Timeline-shaped events for active findings whose CVE is KEV-listed
    (known-exploited in the wild), derive-on-read like ``findings_sla.sla_events``.

    One event per active finding carrying a ``kev=True`` threat block (so the
    caller must ``annotate``/``annotate_offline`` first), dated at the finding's
    ``first_seen_at`` — when it entered the inventory; KEV membership itself is
    re-derived each build, with no second table to record "when we learned KEV".
    Shape matches ``timeline.build_events`` rows: ``{scan_id: None, at, type:
    'new_kev', title, severity, section}``. Severity is fixed ``high`` — a
    known-exploited finding is a 'fix now' signal regardless of its base severity,
    which is preserved in the title. De-dup/ordering are handled by the builder."""
    out: List[Dict] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        threat = f.get('threat')
        if not isinstance(threat, dict) or not threat.get('kev'):
            continue
        sev = str(f.get('severity') or 'info').strip().lower() or 'info'
        title = (f"[{sev}] {f.get('title') or ''} — "
                 f"известно эксплуатируется (KEV)").strip()
        out.append({'scan_id': None, 'at': f.get('first_seen_at'),
                    'type': 'new_kev', 'title': title,
                    'severity': 'high', 'section': 'findings'})
    return out


def summarize(findings: List[Dict]) -> Dict[str, int]:
    """Counts for the report/console card (operates on annotated findings)."""
    out = {'kev': 0, 'epss_high': 0, 'epss_medium': 0, 'enriched': 0}
    for f in findings or []:
        threat = f.get('threat') if isinstance(f, dict) else None
        if not isinstance(threat, dict):
            continue
        out['enriched'] += 1
        if threat.get('kev'):
            out['kev'] += 1
        if threat.get('tier') == 'high' and not threat.get('kev'):
            out['epss_high'] += 1
        elif threat.get('tier') == 'medium':
            out['epss_medium'] += 1
    return out
