"""core/osv_correlation.py
Active CVE correlation for detected front-end JS libraries via OSV.dev.

Where :mod:`core.dependency_audit` flags vulnerable library versions against a
small *bundled, hand-maintained* table (offline, deterministic), this module asks
the public OSV.dev API for the live advisory set affecting each detected
``(library, version)`` — keeping the CVE data current without hardcoding it. It is
**active recon** (one HTTP POST per detected library), so it is strictly opt-in in
the pipeline and *supersedes* the bundled table for the libraries it covers (the
table stays as the offline fallback when this is disabled or returns nothing).

Following the active-recon module pattern (``asn_intel`` / ``dns_intel``): the
network is a single injectable seam (``_post_json``), every lookup is TTL-cached,
parsing is pure and offline-testable (architectural invariant I5), stdlib only
(urllib + json — no new dependency, I1), and any failure degrades silently rather
than aborting the scan.
"""

import json
from typing import Callable, Dict, List, Optional

from utils.browser_utils import SessionBuilder
from utils.http_retry import decompress, urlopen_retry
from utils.scan_cache import TTLCache

_OSV_QUERY_URL = 'https://api.osv.dev/v1/query'
_FETCH_TIMEOUT = 12.0
# Cap advisories per library so a noisy package can't bloat the report.
VULN_CAP = 12

# dependency_audit library key -> OSV (ecosystem, package). Default when a key is
# absent: npm with the same name. Only the exceptions need listing — AngularJS
# 1.x ships on npm as "angular" (the key already is "angular", so it maps 1:1);
# every other detected key (jquery, jquery-ui, react, vue, lodash, bootstrap,
# moment, handlebars, dompurify, axios, underscore, marked) is its own npm name.
_PACKAGE_MAP: Dict[str, tuple] = {}

# Session TTL cache (mirrors recon's GeoIP / asn_intel cache) so re-scanning a
# host within the hour doesn't re-hit OSV. Empty results are cached too (an empty
# list is not None), so a clean library isn't re-queried.
_CACHE = TTLCache(ttl_seconds=3600)

# Reuse the bundled audit's source tag so findings_adapter's category mapping
# ('dependency-audit' -> 'dependency') and the F1 lifecycle treat OSV findings
# exactly like the bundled ones (this is the same producer, better data).
_SOURCE = 'dependency-audit'


def clear_cache() -> int:
    """Drop the cached lookups; returns how many entries were cleared (for the
    Settings 'clear cache' action, like asn_intel.clear_cache)."""
    n = len(_CACHE)
    _CACHE.clear()
    return n


def _ecosystem_package(lib: str) -> tuple:
    return _PACKAGE_MAP.get(lib, ('npm', lib))


# ── network seam (injectable; never hit in tests) ────────────────────────────

def _post_json(url: str, payload: Dict, timeout: float = _FETCH_TIMEOUT,
               profile: str = 'chrome_windows') -> str:
    """POST ``payload`` as JSON to ``url``; return decoded text, or '' on any
    failure. The single network seam — tests inject a fake so the pure parsing and
    aggregation never touch the network (mirrors graphql_discovery._post_raw)."""
    import urllib.request
    try:
        body = json.dumps(payload).encode('utf-8')
        headers = SessionBuilder(profile).get_headers()
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')
        raw, resp_headers = urlopen_retry(req, timeout, attempts=2)
        return decompress(raw, resp_headers).decode('utf-8', 'ignore')
    except Exception:   # noqa: BLE001 — a failed lookup degrades, never aborts
        return ''


# ── severity mapping ─────────────────────────────────────────────────────────

# Advisory severity label -> the vuln scanner's 3-bucket vocabulary
# (High/Medium/Info), matching how external_tools folds nuclei severities so the
# weighted risk score stays consistent. The scanner has no Critical/Low buckets,
# so Critical collapses into High and Low into Info.
def _bucket_from_label(label: str) -> str:
    s = (label or '').upper().strip()
    if s in ('CRITICAL', 'HIGH'):
        return 'High'
    if s in ('MODERATE', 'MEDIUM'):
        return 'Medium'
    return 'Info'   # LOW / unknown


def _bucket_from_score(score: float) -> str:
    if score >= 7.0:
        return 'High'
    if score >= 4.0:
        return 'Medium'
    return 'Info'


def _severity_of(vuln: Dict) -> str:
    """Best-effort severity for one OSV vuln object → High/Medium/Info.

    Prefers the GHSA-style ``database_specific.severity`` string (reliably present
    for npm advisories); falls back to a *numeric* CVSS score when the severity
    entry carries one (the CVSS vector string is intentionally not re-scored — we
    don't reimplement the CVSS formula); defaults to Medium when nothing is given.
    """
    dbspec = vuln.get('database_specific')
    if isinstance(dbspec, dict):
        label = str(dbspec.get('severity') or '').upper().strip()
        if label in ('CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW'):
            return _bucket_from_label(label)
    sev = vuln.get('severity')
    if isinstance(sev, list):
        for entry in sev:
            if isinstance(entry, dict):
                try:
                    return _bucket_from_score(float(entry.get('score')))
                except (TypeError, ValueError):
                    continue   # a CVSS vector string, not a number → skip
    return 'Medium'


# ── pure parser ──────────────────────────────────────────────────────────────

def _parse_osv(text: str) -> List[Dict]:
    """OSV ``/v1/query`` response → ``[{id, cve, severity, summary}]``.

    ``cve`` is the list of CVE aliases (advisory ``id`` — e.g. a GHSA — is kept
    separately). Malformed / empty input degrades to an empty list."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return []
    vulns = doc.get('vulns') if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        return []
    out: List[Dict] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        vid = str(v.get('id') or '')
        aliases = v.get('aliases') or []
        cves = [a for a in aliases if isinstance(a, str) and a.startswith('CVE-')]
        summary = (v.get('summary') or v.get('details') or '')
        out.append({
            'id': vid,
            'cve': cves,
            'severity': _severity_of(v),
            'summary': str(summary).strip()[:300],
        })
    return out


# ── cached lookup + aggregation (pure given the injected post) ───────────────

def correlate(libraries: List[Dict], *,
              post: Optional[Callable] = None) -> Dict[str, List[Dict]]:
    """Query OSV for each detected ``{library, version}`` and return
    ``{library_key: [vuln dicts]}`` for libraries that have advisories.

    Each ``(ecosystem, package, version)`` is TTL-cached. ``post`` is the injected
    network seam (defaults to :func:`_post_json`); pure when it is injected."""
    post = post or _post_json
    out: Dict[str, List[Dict]] = {}
    for lib in libraries or []:
        key = lib.get('library')
        version = lib.get('version')
        if not key or not version:
            continue
        ecosystem, package = _ecosystem_package(key)
        vulns = _CACHE.get_or_compute(
            ('osv', ecosystem, package, version),
            lambda eco=ecosystem, pkg=package, ver=version: _parse_osv(
                post(_OSV_QUERY_URL,
                     {'package': {'name': pkg, 'ecosystem': eco}, 'version': ver})),
        )
        if vulns:
            out[key] = vulns[:VULN_CAP]
    return out


def to_findings(name: str, version: str, vulns: List[Dict]) -> List[Dict]:
    """Shape a library's OSV vulns into vuln-scanner findings.

    Each finding carries ``source='dependency-audit'`` (so it folds into the risk
    score like the bundled audit) and an explicit ``discriminator`` = the CVE/
    advisory id, so distinct CVEs at one library stay distinct findings under the
    F1 fingerprint (which otherwise masks the digit runs in the title)."""
    findings: List[Dict] = []
    for v in vulns:
        cves = v.get('cve') or []
        ident = cves[0] if cves else (v.get('id') or '')
        label = ', '.join(cves) or v.get('id') or ''
        suffix = f' ({label})' if label else ''
        summary = v.get('summary') or 'Известная уязвимость (OSV).'
        findings.append({
            'severity': v.get('severity', 'Medium'),
            'title': f'Уязвимая библиотека: {name} {version}{suffix}',
            'detail': f"OSV/{v.get('id', '')}: {summary}".strip(),
            'source': _SOURCE,
            'discriminator': ident,
        })
    return findings
