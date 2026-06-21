"""core/nvd_provider.py
NVD (National Vulnerability Database) enrichment for a single CVE id.

CVE Intelligence (EPIC 3) correlates a ``(library, version)`` to its CVEs via OSV
(the npm-ecosystem source); NVD is queried *per CVE id* to add the authoritative
fields OSV does not reliably carry: the numeric **CVSS base score**, the
**published date**, and the canonical English **summary**. So NVD's role here is
enrichment, not correlation — which sidesteps NVD's CPE-matching (deferred to a
later phase) and keeps phase 1 JS-only.

Active recon, opt-in, keyless by default (an NVD API key in settings raises the
rate limit but is never required — no mandatory cloud dependency, per the EPIC).
Follows the established provider pattern (``asn_intel`` / ``osv_correlation``): the
network is a single injectable seam (``_get_text``), parsing is pure and
offline-testable (invariant I5), stdlib only (urllib + json, I1), and any failure
degrades to ``None`` rather than aborting the scan. The CVE 3-bucket severity
mapping is reused from ``osv_correlation`` so the platform never grows a second
scoring system.
"""

import json
import re
from typing import Callable, Dict, List, Optional

from core.osv_correlation import _bucket_from_label, _bucket_from_score

# A real CWE identifier (CWE-79, …); NVD also emits placeholders like
# "NVD-CWE-noinfo" / "NVD-CWE-Other" which carry no weakness and are skipped.
_CWE_RE = re.compile(r'^CWE-\d+$')
from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

_NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
_FETCH_TIMEOUT = 12.0


def _api_key() -> str:
    """Optional NVD API key from settings (raises the rate limit; not required)."""
    try:
        from core.config import load_settings
        return str((load_settings() or {}).get('nvd_api_key') or '').strip()
    except Exception:   # noqa: BLE001 — settings unavailable → keyless, never fatal
        return ''


# ── network seam (injectable; never hit in tests) ────────────────────────────

def _get_text(url: str, timeout: float = _FETCH_TIMEOUT,
              profile: str = 'chrome_windows') -> str:
    """GET ``url`` and return decoded text, or '' on any failure. The single
    network seam — tests inject a fake so the pure parser never touches the net."""
    try:
        req = SessionBuilder(profile).make_request(url)
        req.add_header('Accept', 'application/json')
        key = _api_key()
        if key:
            req.add_header('apiKey', key)
        return urlopen_text(req, timeout, attempts=2)
    except Exception:   # noqa: BLE001 — a failed lookup degrades, never aborts
        return ''


# ── pure parser ──────────────────────────────────────────────────────────────

def _best_cvss(metrics: Dict) -> tuple:
    """Pick the strongest available CVSS (v3.1 > v3.0 > v2) → (score, severity).

    Returns ``(float|None, label|'')``. v3 carries ``baseSeverity`` in cvssData;
    v2 carries it at the metric level. Missing/garbled metrics degrade to
    ``(None, '')``."""
    if not isinstance(metrics, dict):
        return None, ''
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = entries[0] if isinstance(entries[0], dict) else {}
        data = entry.get('cvssData') if isinstance(entry.get('cvssData'), dict) else {}
        try:
            score = float(data.get('baseScore'))
        except (TypeError, ValueError):
            score = None
        severity = str(data.get('baseSeverity') or entry.get('baseSeverity') or '')
        if score is not None or severity:
            return score, severity
    return None, ''


def _extract_cwes(cve: Dict) -> List[str]:
    """The CWE id(s) NVD attributes to a CVE (``weaknesses[].description[].value``),
    de-duplicated and order-preserved. Placeholders (``NVD-CWE-noinfo``/``-Other``)
    are skipped — only concrete ``CWE-NNN`` ids are kept."""
    out: List[str] = []
    for w in cve.get('weaknesses') or []:
        if not isinstance(w, dict):
            continue
        for d in w.get('description') or []:
            val = str(d.get('value') or '').strip() if isinstance(d, dict) else ''
            if _CWE_RE.match(val) and val not in out:
                out.append(val)
    return out


def _parse_nvd(text: str, cve_id: str) -> Optional[Dict]:
    """NVD ``/cves/2.0`` response → ``{cvss, severity, published, summary, cwe,
    source}`` for ``cve_id``, or ``None`` when absent/malformed.

    ``severity`` is the 3-bucket vocabulary (High/Medium/Info) via the shared OSV
    mapping — preferring the CVSS severity label, falling back to the numeric
    score; ``cvss`` keeps the exact numeric base score for display; ``cwe`` is the
    authoritative per-CVE weakness id(s) NVD attributes (empty list when none)."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None
    vulns = doc.get('vulnerabilities') if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        return None
    for item in vulns:
        cve = item.get('cve') if isinstance(item, dict) else None
        if not isinstance(cve, dict) or str(cve.get('id')) != str(cve_id):
            continue
        score, label = _best_cvss(cve.get('metrics'))
        severity = (_bucket_from_label(label) if label
                    else _bucket_from_score(score) if score is not None else 'Medium')
        descriptions = cve.get('descriptions') or []
        summary = ''
        for d in descriptions:
            if isinstance(d, dict) and d.get('lang') == 'en':
                summary = str(d.get('value') or '')
                break
        published = str(cve.get('published') or '')[:10]   # date part only
        return {'cvss': score, 'severity': severity, 'published': published,
                'summary': summary.strip()[:300], 'cwe': _extract_cwes(cve),
                'source': 'nvd'}
    return None


# ── enrichment (pure given the injected get) ─────────────────────────────────

def enrich(cve_id: str, *, get: Optional[Callable] = None) -> Optional[Dict]:
    """Authoritative enrichment for one CVE id from NVD, or ``None``.

    ``get`` is the injected network seam (defaults to :func:`_get_text`); pure
    when it is injected. Only real ``CVE-…`` ids are queried (NVD is CVE-keyed —
    a GHSA-only advisory has no NVD record and returns ``None``)."""
    cid = str(cve_id or '').strip().upper()
    if not cid.startswith('CVE-'):
        return None
    get = get or _get_text
    return _parse_nvd(get(_NVD_URL.format(cve=cid)), cid)
