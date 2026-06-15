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
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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
# A CVE id anywhere in a finding's fields — the cross-scanner merge key (B).
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
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


def extract_cve(raw: Dict) -> Optional[str]:
    """The CVE id a raw finding refers to (upper-cased), or ``None``.

    The cross-scanner merge key (B): an explicit ``cve`` field, the
    ``discriminator`` (OSV sets it to the CVE), or a ``CVE-####-…`` literal in the
    title/detail (nuclei carries it in the template id). GHSA-only advisories have
    no CVE → they keep their own identity (not merged)."""
    explicit = raw.get('cve')
    if isinstance(explicit, (list, tuple)):
        explicit = explicit[0] if explicit else ''
    for value in (explicit, raw.get('discriminator', ''),
                  raw.get('title', ''), raw.get('detail', '')):
        m = _CVE_RE.search(str(value or ''))
        if m:
            return m.group(0).upper()
    return None


def _sources_of(raw: Dict) -> List[str]:
    """Every scanner/source that reported a raw finding (a pre-merged ``sources``
    list wins, else the single ``source``)."""
    multi = raw.get('sources')
    if isinstance(multi, (list, tuple)):
        return [str(s).strip() for s in multi if str(s).strip()]
    one = str(raw.get('source', '')).strip()
    return [one] if one else []


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
    sources: List[str] = field(default_factory=list)
    # Producer-supplied knowledge (F-O2) — non-identity, optional. When present
    # (e.g. a nuclei template's info.*) it persists in evidence and wins over the
    # finding_knowledge catalog at display time.
    description: str = ''
    impact: str = ''
    remediation: str = ''

    @property
    def id(self) -> str:
        return fingerprint(self.category, self.rule_id, self.location,
                           self.discriminator)

    def to_store(self) -> Dict:
        """Shape expected by :meth:`FindingsStore.upsert` — masked evidence only."""
        evidence = {'location': self.location, 'source': self.source,
                    'detail': self.detail, 'discriminator': self.discriminator,
                    'description': self.description, 'impact': self.impact,
                    'remediation': self.remediation}
        # Keep the cross-scanner reference list only when several tools agree.
        if len(self.sources) > 1:
            evidence['sources'] = self.sources
        return {
            'id': self.id, 'category': self.category, 'rule_id': self.rule_id,
            'title': self.title, 'severity': normalize_severity(self.severity),
            'evidence': {k: v for k, v in evidence.items() if v},
        }


def _knowledge(raw: Dict) -> Dict[str, str]:
    """Producer-supplied description/impact/remediation (optional, F-O2)."""
    return {k: str(raw.get(k) or '') for k in ('description', 'impact',
                                               'remediation')}


def from_raw(raw: Dict) -> Finding:
    """Map one raw scanner finding dict to a :class:`Finding` (pure).

    A finding carrying a CVE gets a *canonical, scanner-agnostic* identity
    (category ``vuln``, rule_id = the CVE), so the same CVE reported by nuclei +
    OSV + dependency-audit collapses to ONE finding (DefectDojo-style dedup).
    Non-CVE findings (headers/cookies/secrets/dns…) keep their existing identity.
    """
    cve = extract_cve(raw)
    if cve:
        return Finding(
            category='vuln',
            rule_id=cve.lower(),
            title=str(raw.get('title', '')),
            severity=str(raw.get('severity', 'Info')),
            location=normalize_location(_location(raw)),
            discriminator='',
            source=str(raw.get('source', '')),
            detail=str(raw.get('detail', '')),
            sources=_sources_of(raw),
            **_knowledge(raw),
        )
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
        sources=_sources_of(raw),
        **_knowledge(raw),
    )


def normalize(raw_findings: List[Dict]) -> List[Finding]:
    """Map a scan's raw findings to Findings, de-duplicated by fingerprint.

    Two raw findings that resolve to the same identity (the same issue reported
    twice, or the same CVE from different scanners) collapse to one — the first
    wins for display, but every reporting source is accumulated onto it."""
    seen: Dict[str, Finding] = {}
    srcs: Dict[str, List[str]] = {}
    for raw in raw_findings or []:
        if not isinstance(raw, dict):
            continue
        f = from_raw(raw)
        bag = srcs.setdefault(f.id, [])
        for s in _sources_of(raw):
            if s and s not in bag:
                bag.append(s)
        seen.setdefault(f.id, f)
    for fid, f in seen.items():
        if len(srcs[fid]) > 1:
            f.sources = srcs[fid]
    return list(seen.values())


def dedup_findings(raw_findings: List[Dict]) -> List[Dict]:
    """Collapse raw findings that share a finding identity (e.g. the same CVE from
    different scanners) into one *raw* dict, accumulating every ``source`` into a
    ``sources`` list. First occurrence wins for display fields. Returns a new list
    — used to dedup the risk-bearing findings before the risk score + the store
    sync, so a CVE counts once and the store keeps one merged finding."""
    out: Dict[str, Dict] = {}
    for raw in raw_findings or []:
        if not isinstance(raw, dict):
            continue
        fid = from_raw(raw).id
        if fid not in out:
            merged = dict(raw)
            merged['sources'] = []
            out[fid] = merged
        for s in _sources_of(raw):
            if s and s not in out[fid]['sources']:
                out[fid]['sources'].append(s)
    return list(out.values())
