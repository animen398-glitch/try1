"""core/findings_adapter.py
Normalize heterogeneous scanner findings into the unified Finding DTO (F1, T1.3).

Every producer in the pipeline (vuln_scanner, dependency_audit, dns_intel,
nuclei, analyzer plugins) appends flat ``{severity, title, detail[, source]}``
dicts into the vulns phase. Findings Management needs a *stable identity* for
each, so this adapter maps a raw finding to a :class:`Finding` carrying the four
fingerprint components — ``category | rule_id | normalized_location |
discriminator`` (see :mod:`core.finding_fingerprint`).

Design (pure adapter — scanners are NOT modified, so backward-compat and the
existing report/Scan-Diff readers are untouched):
  * A raw finding may already carry explicit ``category`` / ``rule_id`` /
    ``location`` / ``discriminator`` — those win (lets a producer opt in later).
  * Otherwise we derive them deterministically:
      - ``category`` — from ``source`` (map), else a title keyword, else 'vuln'.
      - ``rule_id`` — a slug of the title with digit runs masked, so volatile
        counts ("Missing security headers (3)" vs "(4)") don't fork identity,
        while embedded distinguishers (cookie name, header name, secret type)
        keep distinct rules distinct.
      - ``location`` — first URL found in detail/source/title, normalized.
      - ``discriminator`` — empty for most; for SECRETS we parse the already
        masked ``key`` + ``preview`` out of the detail so two different keys at
        one location stay distinct WITHOUT any plaintext entering the id.

Pure and stdlib-only (I1/I5).
"""

import re
from dataclasses import dataclass
from typing import Dict, List

from core.finding_fingerprint import fingerprint, normalize_location

# Producer ``source`` value → finding category.
_SOURCE_CATEGORY = {
    'dns': 'dns',
    'dependency-audit': 'dependency',
    'nuclei': 'vuln',
    'secret': 'secret',
}

# Fallback classification by a keyword in the title (first match wins), used
# only when neither an explicit category nor a known source is present.
_TITLE_CATEGORY = (
    ('secret', 'secret'),
    ('cookie', 'cookie'),
    ('content-security-policy', 'header'),
    ('csp', 'header'),
    ('hsts', 'header'),
    ('referrer-policy', 'header'),
    ('x-frame-options', 'header'),
    ('security headers', 'header'),
    ('header', 'header'),
    ('cms/stack', 'tech'),
    ('framework globals', 'tech'),
    ('pwa', 'tech'),
    ('sensitive path', 'endpoint'),
    ('plain http', 'transport'),
)

# Severity synonyms → the canonical lowercase scale.
_SEVERITY = {
    'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
    'info': 'info', 'informational': 'info', 'warning': 'medium', 'error': 'high',
}

_URL_RE = re.compile(r'https?://[^\s\'"|]+')
_DIGIT_RE = re.compile(r'\d+')
_SLUG_RE = re.compile(r'[^a-z0-9]+')
# Secret detail shape: key='<k>'  =>  '<preview>'  |  <url>
_SECRET_RE = re.compile(r"key='(?P<key>[^']*)'\s*=>\s*'(?P<preview>[^']*)'")


def normalize_severity(severity) -> str:
    """Map any producer's severity to the canonical lowercase scale."""
    return _SEVERITY.get(str(severity or '').strip().lower(), 'info')


def _slug(text: str) -> str:
    """Stable slug of a title: digit runs masked, non-alphanumerics collapsed."""
    masked = _DIGIT_RE.sub('#', str(text or '').lower())
    return _SLUG_RE.sub('-', masked).strip('-')


def _category(raw: Dict) -> str:
    if raw.get('category'):
        return str(raw['category']).strip().lower()
    src = str(raw.get('source', '')).strip().lower()
    if src in _SOURCE_CATEGORY:
        return _SOURCE_CATEGORY[src]
    title = str(raw.get('title', '')).lower()
    for keyword, category in _TITLE_CATEGORY:
        if keyword in title:
            return category
    return 'vuln'


def _location(raw: Dict) -> str:
    if raw.get('location'):
        return str(raw['location'])
    for value in (raw.get('detail', ''), raw.get('source', ''),
                  raw.get('title', '')):
        m = _URL_RE.search(str(value))
        if m:
            return m.group(0)
    return ''


def _discriminator(raw: Dict, category: str) -> str:
    if raw.get('discriminator'):
        return str(raw['discriminator'])
    # Secrets: distinguish distinct keys at one location via the masked
    # key + preview already present in the detail (no plaintext is introduced).
    if category == 'secret':
        m = _SECRET_RE.search(str(raw.get('detail', '')))
        if m:
            return f"{m.group('key')}:{m.group('preview')}"
    return ''


@dataclass
class Finding:
    """The unified, identity-bearing finding. ``id`` is its fingerprint."""
    category: str
    rule_id: str
    title: str
    severity: str
    location: str = ''
    discriminator: str = ''
    source: str = ''
    detail: str = ''

    @property
    def id(self) -> str:
        return fingerprint(self.category, self.rule_id, self.location,
                           self.discriminator)

    def to_store(self) -> Dict:
        """Shape expected by :meth:`FindingsStore.upsert` — masked evidence only."""
        evidence = {'location': self.location, 'source': self.source,
                    'detail': self.detail, 'discriminator': self.discriminator}
        return {
            'id': self.id, 'category': self.category, 'rule_id': self.rule_id,
            'title': self.title, 'severity': normalize_severity(self.severity),
            'evidence': {k: v for k, v in evidence.items() if v},
        }


def from_raw(raw: Dict) -> Finding:
    """Map one raw scanner finding dict to a :class:`Finding` (pure)."""
    category = _category(raw)
    return Finding(
        category=category,
        rule_id=str(raw.get('rule_id') or _slug(raw.get('title', ''))),
        title=str(raw.get('title', '')),
        severity=str(raw.get('severity', 'Info')),
        location=normalize_location(_location(raw)),
        discriminator=_discriminator(raw, category),
        source=str(raw.get('source', '')),
        detail=str(raw.get('detail', '')),
    )


def normalize(raw_findings: List[Dict]) -> List[Finding]:
    """Map a scan's raw findings to Findings, de-duplicated by fingerprint.

    Two raw findings that resolve to the same identity (e.g. the same issue
    reported twice) collapse to one — the store then upserts each id once."""
    seen: Dict[str, Finding] = {}
    for raw in raw_findings or []:
        if not isinstance(raw, dict):
            continue
        f = from_raw(raw)
        seen.setdefault(f.id, f)
    return list(seen.values())
