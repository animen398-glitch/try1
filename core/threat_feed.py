"""core/threat_feed.py
KEV / EPSS exploitability feeds — pure parsers + a single injectable network seam.

Two keyless, public feeds key findings' CVEs to real-world exploitability:

  * **CISA KEV** (Known Exploited Vulnerabilities) — a single catalog JSON; a CVE
    in it is being exploited in the wild. Public domain.
  * **FIRST EPSS** (Exploit Prediction Scoring System) — a per-CVE probability
    (0–1) + percentile of exploitation in the next 30 days. Free, keyless;
    queried per-CVE (comma-batched) so we never download the full daily dataset.

Follows the established provider pattern (``nvd_provider`` / ``osv_correlation``):
the network is one injectable seam (``_get_text``), parsing is pure and
offline-testable, stdlib only (urllib + json), and any failure degrades to an
empty result rather than aborting. Persistence + orchestration live in
``core.threat_intel`` (which caches per-CVE results in :class:`CVEStore`); this
module only fetches and parses.
"""

import json
from typing import Callable, Dict, List, Optional

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text


KEV_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
           'known_exploited_vulnerabilities.json')
EPSS_URL = 'https://api.first.org/data/v1/epss?cve={cves}'
_FETCH_TIMEOUT = 12.0
# KEV/EPSS both refresh daily, so a day of cache freshness is plenty and keeps
# offline runs cheap (one fetch per day). Overridable by the orchestrator.
DEFAULT_FRESH_SECONDS = 24 * 3600
# Comma-batch size for the EPSS per-CVE query (keeps the URL bounded).
EPSS_BATCH = 100


def _get_text(url: str, timeout: float = _FETCH_TIMEOUT,
              profile: str = 'chrome_windows') -> str:
    """GET ``url`` → decoded text, or '' on any failure. The single network seam
    — tests inject a fake so the pure parsers never touch the net."""
    try:
        req = SessionBuilder(profile).make_request(url)
        req.add_header('Accept', 'application/json')
        return urlopen_text(req, timeout, attempts=2)
    except Exception:   # noqa: BLE001 — a failed lookup degrades, never aborts
        return ''


def _norm_cve(value) -> str:
    return str(value or '').strip().upper()


# ── pure parsers ──────────────────────────────────────────────────────────────

def parse_kev(text: str) -> Dict[str, str]:
    """CISA KEV catalog JSON → ``{CVE-ID: date_added}`` (empty on any problem)."""
    try:
        data = json.loads(text or '')
    except (ValueError, TypeError):
        return {}
    out: Dict[str, str] = {}
    for item in (data.get('vulnerabilities') if isinstance(data, dict) else None) or []:
        if not isinstance(item, dict):
            continue
        cve = _norm_cve(item.get('cveID'))
        if cve:
            out[cve] = str(item.get('dateAdded') or '')
    return out


def _to_float(value) -> Optional[float]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != f:   # NaN guard
        return None
    return max(0.0, min(1.0, f))


def parse_epss(text: str) -> Dict[str, Dict]:
    """FIRST EPSS API JSON → ``{CVE-ID: {'score': float, 'percentile': float}}``."""
    try:
        data = json.loads(text or '')
    except (ValueError, TypeError):
        return {}
    out: Dict[str, Dict] = {}
    for item in (data.get('data') if isinstance(data, dict) else None) or []:
        if not isinstance(item, dict):
            continue
        cve = _norm_cve(item.get('cve'))
        if not cve:
            continue
        out[cve] = {
            'score': _to_float(item.get('epss')),
            'percentile': _to_float(item.get('percentile')),
        }
    return out


# ── network fetchers (injectable ``get``) ──────────────────────────────────────

def fetch_kev(*, get: Optional[Callable[[str], str]] = None) -> Dict[str, str]:
    """Fetch + parse the KEV catalog; ``{}`` on any failure (soft-degrade)."""
    getter = get or _get_text
    return parse_kev(getter(KEV_URL))


def fetch_epss(cve_ids: List[str], *,
               get: Optional[Callable[[str], str]] = None,
               batch: int = EPSS_BATCH) -> Dict[str, Dict]:
    """Fetch + parse EPSS for the given CVEs (comma-batched). ``{}`` on failure."""
    getter = get or _get_text
    wanted = sorted({_norm_cve(c) for c in (cve_ids or []) if _norm_cve(c)})
    out: Dict[str, Dict] = {}
    size = max(1, int(batch))
    for start in range(0, len(wanted), size):
        chunk = wanted[start:start + size]
        url = EPSS_URL.format(cves=','.join(chunk))
        out.update(parse_epss(getter(url)))
    return out
