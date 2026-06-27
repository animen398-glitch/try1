"""core/cve_intel.py
CVE Intelligence engine — the orchestrator (EPIC 3, phase 1: JS libraries).

Ties the pieces together into the platform's CVE story:

    detected JS library (name, version)
        → OSV correlation        (which CVEs affect it — core.osv_correlation)
        → NVD enrichment          (authoritative CVSS / published date — core.nvd_provider)
        → persistent cache        (offline after the base is loaded — core.cve_store)
        → unified CVE records      (id · CVE · severity · CVSS · published · summary)
        → findings                 (fold into the vuln phase → risk / dashboard / report)

Why this layer (instead of calling OSV directly as ``_phase_osv`` used to): it owns
the **caching policy** the EPIC requires — a fresh-enough cached lookup skips the
network entirely, and when the network is *down* a stale cache is still used (so a
re-scan works offline), which OSV's session-only in-memory cache cannot express. It
distinguishes "library is clean" (provider responded, empty) from "provider
unreachable" (empty response string) so a fixed library isn't pinned to a stale hit.

Pure given the injected seams (``osv_post`` / ``nvd_get`` / ``store``) — invariant
I5; stdlib only (I1); every failure degrades, never aborts. The findings it emits
carry ``source='dependency-audit'`` and a CVE ``discriminator`` exactly like the OSV
path did, so Findings Management, the cross-scanner CVE dedup (findings_adapter), and
the risk score treat them unchanged — the score still counts a CVE once via its
severity (the "CVE Risk Score" is a derived *display metric*, never a second addend).
"""

from typing import Callable, Dict, List, Optional

from core import nvd_provider as nvd
from core import osv_correlation as osv
from core.cve_store import CVEStore

# A cached lookup younger than this skips the network; older is refreshed when the
# network is reachable, or reused as-is when it is not (offline fallback).
DEFAULT_FRESH_SECONDS = 7 * 24 * 3600
_SOURCE = 'dependency-audit'   # same producer tag as the bundled/OSV path


def clear_cache() -> int:
    """Drop the persistent CVE cache; returns rows removed (for Settings)."""
    return CVEStore().clear()


# ── per-library OSV lookup with the persistent/offline cache policy ───────────

def _lib_vulns(eco: str, pkg: str, ver: str, store: CVEStore,
               osv_post: Callable, fresh_seconds: float) -> List[Dict]:
    """Advisories for one library: a fresh cache hit, else a live OSV query (cached),
    else — when OSV is unreachable — the stale cache (offline fallback)."""
    cached = store.get_lib_cves(eco, pkg, ver)
    if cached and cached['age'] <= fresh_seconds:
        return cached['vulns']
    raw = osv_post(osv._OSV_QUERY_URL,
                   {'package': {'name': pkg, 'ecosystem': eco}, 'version': ver})
    if raw:   # provider responded (success — even an empty advisory set is fresh)
        vulns = osv._parse_osv(raw)[:osv.VULN_CAP]
        store.put_lib_cves(eco, pkg, ver, vulns)
        return vulns
    if cached:   # provider unreachable → reuse the stale cache (offline)
        return cached['vulns']
    return []


def _enrich(vuln: Dict, store: CVEStore, nvd_get: Callable,
            fresh_seconds: float) -> Dict:
    """Enrich one advisory with NVD (authoritative CVSS / published / severity),
    cached per CVE. The OSV fields stand in when NVD has nothing."""
    record = dict(vuln)
    record.setdefault('source', 'osv')
    cves = vuln.get('cve') or []
    cve_id = cves[0] if cves else ''
    if not cve_id:
        return record
    cached = store.get_cve_detail(cve_id)
    detail = cached if (cached and cached['age'] <= fresh_seconds) else None
    if detail is None:
        fetched = nvd.enrich(cve_id, get=nvd_get)
        if fetched:
            store.put_cve_detail(cve_id, fetched)
            detail = fetched
        elif cached:                      # NVD unreachable → stale enrichment
            detail = cached
    if detail:
        if detail.get('cvss') is not None:
            record['cvss'] = detail['cvss']
        if detail.get('published'):
            record['published'] = detail['published']
        if detail.get('severity'):
            record['severity'] = detail['severity']   # NVD severity is authoritative
        if detail.get('summary') and not record.get('summary'):
            record['summary'] = detail['summary']
        if detail.get('cwe'):
            record['cwe'] = detail['cwe']   # authoritative per-CVE weakness id(s)
        record['source'] = 'osv+nvd'
    return record


def correlate(libraries: List[Dict], *, store: Optional[CVEStore] = None,
              osv_post: Optional[Callable] = None,
              nvd_get: Optional[Callable] = None,
              fresh_seconds: float = DEFAULT_FRESH_SECONDS) -> Dict[str, List[Dict]]:
    """Correlate detected libraries to enriched CVE records.

    Returns ``{library_key: [unified CVE record]}`` for libraries with advisories.
    Each record is ``{id, cve:[…], severity, cvss, published, summary, source}``.
    Seams are injected in tests so nothing touches the network."""
    own_store = store is None
    store = store or CVEStore()
    if own_store:
        # Self-bound the on-disk cache once per run (best-effort; never blocks a
        # correlation). An injected store (tests) is left untouched.
        try:
            store.prune()
        except Exception:
            pass
    osv_post = osv_post or osv._post_json
    nvd_get = nvd_get or nvd._get_text
    out: Dict[str, List[Dict]] = {}
    for lib in libraries or []:
        key, ver = lib.get('library'), lib.get('version')
        if not key or not ver:
            continue
        eco, pkg = osv._ecosystem_package(key)
        vulns = _lib_vulns(eco, pkg, ver, store, osv_post, fresh_seconds)
        if not vulns:
            continue
        out[key] = [_enrich(v, store, nvd_get, fresh_seconds) for v in vulns]
    return out


# ── findings + summary (downstream: risk / dashboard / report) ───────────────

def to_findings(name: str, version: str, vulns: List[Dict]) -> List[Dict]:
    """Shape a library's enriched CVE records into vuln-scanner findings.

    Same producer tag (``dependency-audit``) and CVE ``discriminator`` as the OSV
    path, so F1 / the cross-scanner CVE dedup / risk treat them unchanged; the
    detail now carries the CVSS score, published date and CWE(s) for display."""
    findings: List[Dict] = []
    for v in vulns:
        cves = v.get('cve') or []
        ident = cves[0] if cves else (v.get('id') or '')
        label = ', '.join(cves) or v.get('id') or ''
        bits = []
        if v.get('cvss') is not None:
            bits.append(f"CVSS {v['cvss']}")
        if v.get('published'):
            bits.append(str(v['published']))
        if v.get('cwe'):
            bits.append(', '.join(v['cwe']))
        meta = f" [{' · '.join(bits)}]" if bits else ''
        summary = v.get('summary') or 'Известная уязвимость.'
        suffix = f' ({label})' if label else ''
        finding = {
            'severity': v.get('severity', 'Medium'),
            'title': f'Уязвимая библиотека: {name} {version}{suffix}',
            'detail': f"{v.get('id', '')}{meta}: {summary}".strip().strip(':').strip(),
            'source': _SOURCE,
            'discriminator': ident,
        }
        if v.get('cwe'):
            finding['cwe'] = v['cwe']   # authoritative per-CVE weakness (NVD)
        findings.append(finding)
    return findings


def summarize(correlated: Dict[str, List[Dict]]) -> Dict:
    """Flat CVE summary for the risk *metric* (not a score addend): unique CVEs
    (deduped by id) counted by severity. ``{total, high, medium, info}``."""
    seen: Dict[str, str] = {}
    for vulns in (correlated or {}).values():
        for v in vulns or []:
            cves = v.get('cve') or []
            cid = cves[0] if cves else (v.get('id') or '')
            if cid and cid not in seen:
                seen[cid] = v.get('severity', 'Medium')
    counts = {'High': 0, 'Medium': 0, 'Info': 0}
    for sev in seen.values():
        counts[sev] = counts.get(sev, 0) + 1
    return {'total': len(seen), 'high': counts['High'],
            'medium': counts['Medium'], 'info': counts['Info']}
