"""core/osint_catalog.py
AI-OSINT Workflow Catalog — a declarative, derive-on-read guide (EXT-OSINT F3).

This is NOT a scanner and makes no network call of its own. It is a curated,
offline catalog of recon workflows — "which reconnaissance chains make sense and
which of our engines back them" — modelled on the Awesome-AI-OSINT taxonomy
(ideas only; nothing copied). It mirrors the pure derive-on-read style of
``finding_knowledge`` / ``compliance``: a static catalog plus thin resolvers that,
given a scan ``report``, report which workflows the scan actually exercised
(coverage) and which optional engines are installed.

Every listed workflow is backed by an engine that already exists in this codebase
— no new scanners, no new data, no risk-score impact (pure guide/coverage). Out
of scope (no engine / heavy AI / ethics): visual intelligence (reverse-image /
face / geolocation / GEOINT), ethnicity analysis, dark-web monitoring.
"""

import copy
from typing import Dict, List, Optional

from core.features import has_bbot, has_lift, has_ocr, has_pdf_text

# Catalog engine token → the report phase whose ``status == 'Success'`` means the
# engine contributed. Several tokens are produced *inside* the recon/osv phases
# (tech fingerprint, dependency audit, infrastructure, cve intel), so they map to
# that phase. Platform capabilities that are not per-scan phases (monitoring /
# timeline / scan diff) map to ``None`` — they are always available, so they never
# count as "missing" coverage.
_ENGINE_PHASE: Dict[str, Optional[str]] = {
    'recon': 'recon', 'infrastructure': 'recon', 'tech_fingerprint': 'recon',
    'dependency_audit': 'recon',
    'subdomains': 'subdomains', 'ct': 'ct', 'asn_intel': 'asn_intel',
    'dns': 'dns', 'emails': 'emails', 'employees': 'employees',
    'osv': 'osv', 'cve_intel': 'osv',
    'security': 'security', 'cookies': 'cookies', 'api': 'api',
    'documents': 'documents', 'historical': 'historical', 'bbot': 'bbot',
    'monitor': None, 'timeline': None, 'scan_diff': None,
}

# The curated workflow set (phase 1). Each ``engine`` token resolves via
# ``_ENGINE_PHASE``; ``optional`` engines strengthen but are not required.
WORKFLOWS: List[Dict] = [
    {
        'id': 'infrastructure-recon',
        'name': 'Infrastructure Recon',
        'category': 'Digital Infrastructure',
        'goal': 'Map the external infrastructure: domain → subdomains → IP → ASN '
                '→ provider/CDN.',
        'engines': ['recon', 'subdomains', 'ct', 'asn_intel', 'infrastructure'],
        'optional': ['bbot'],
        'produces': ['assets', 'attack_surface'],
        'network': 'active',
    },
    {
        'id': 'subdomain-takeover-surface',
        'name': 'Subdomain & Takeover Surface',
        'category': 'Digital Infrastructure',
        'goal': 'Enumerate subdomains and flag dangling records vulnerable to '
                'takeover.',
        'engines': ['subdomains', 'ct', 'dns'],
        'optional': ['bbot'],
        'produces': ['assets', 'findings'],
        'network': 'active',
    },
    {
        'id': 'email-people-surface',
        'name': 'Email & People Surface',
        'category': 'Human-Centric',
        'goal': 'Harvest exposed e-mail addresses and named employees, and check '
                'e-mail authentication (SPF/DMARC).',
        'engines': ['emails', 'employees', 'dns'],
        'optional': [],
        'produces': ['report', 'findings'],
        'network': 'active',
    },
    {
        'id': 'technology-dependency-risk',
        'name': 'Technology & Dependency Risk',
        'category': 'Digital Infrastructure',
        'goal': 'Fingerprint the tech stack and flag vulnerable / outdated '
                'JS dependencies.',
        'engines': ['recon', 'tech_fingerprint', 'dependency_audit'],
        'optional': ['osv', 'cve_intel'],
        'produces': ['findings', 'attack_surface'],
        'network': 'passive',
    },
    {
        'id': 'web-exposure-audit',
        'name': 'Web Exposure Audit',
        'category': 'Digital Infrastructure',
        'goal': 'Find leaking source maps, reachable GraphQL, weak cookies and '
                'leaked secrets.',
        'engines': ['security', 'cookies', 'api'],
        'optional': ['documents'],
        'produces': ['findings'],
        'network': 'active',
    },
    {
        'id': 'historical-archive-recon',
        'name': 'Historical & Archive Recon',
        'category': 'Information Monitoring',
        'goal': 'Recover interesting archived URLs and the certificate-'
                'transparency history.',
        'engines': ['historical', 'ct'],
        'optional': [],
        'produces': ['assets', 'findings'],
        'network': 'active',
    },
    {
        'id': 'cve-threat-correlation',
        'name': 'CVE / Threat Correlation',
        'category': 'Information Monitoring',
        'goal': 'Correlate detected libraries with live advisory/CVE data.',
        'engines': ['osv', 'cve_intel', 'dependency_audit'],
        'optional': [],
        'produces': ['findings'],
        'network': 'active',
    },
    {
        'id': 'continuous-monitoring',
        'name': 'Continuous Monitoring & Change Tracking',
        'category': 'Information Monitoring',
        'goal': 'Re-scan on a schedule and surface what changed between scans.',
        'engines': ['monitor', 'timeline', 'scan_diff'],
        'optional': [],
        'produces': ['timeline', 'alerts'],
        'network': 'active',
    },
    {
        'id': 'external-recon-bbot',
        'name': 'External Recon Enrichment (BBOT)',
        'category': 'Integrated Platforms',
        'goal': 'Enrich the asset inventory with an external recon engine.',
        'engines': ['bbot'],
        'optional': [],
        'produces': ['assets', 'findings'],
        'network': 'active',
    },
    {
        'id': 'document-intelligence',
        'name': 'Document Intelligence',
        'category': 'Human-Centric',
        'goal': 'Mine captured documents (PDF/images/config files) for secrets '
                'and sensitive data.',
        'engines': ['documents'],
        'optional': [],
        'produces': ['findings'],
        'network': 'passive',
    },
]


def catalog() -> List[Dict]:
    """The full workflow catalog (a deep copy — callers may not mutate the
    module constant)."""
    return copy.deepcopy(WORKFLOWS)


def _phase_ok(report: Dict, phase: str) -> bool:
    phases = report.get('phases') if isinstance(report, dict) else None
    p = phases.get(phase) if isinstance(phases, dict) else None
    return isinstance(p, dict) and p.get('status') == 'Success'


def _engine_ran(report: Dict, engine: str) -> bool:
    """Whether a catalog engine contributed to this scan. Platform-capability
    engines (phase ``None``) are always considered present."""
    phase = _ENGINE_PHASE.get(engine, engine)
    if phase is None:
        return True
    return _phase_ok(report, phase)


def assess(report: Dict) -> List[Dict]:
    """Annotate every workflow with this scan's coverage.

    Each entry gains ``status`` (``covered`` = all required engines ran,
    ``partial`` = some, ``not_run`` = none), ``ran``/``missing`` (required engine
    tokens), and ``optional_ran``. Pure/offline — reads only ``report['phases']``
    statuses (the same source exec_summary/scan_diff use, I3)."""
    report = report if isinstance(report, dict) else {}
    out: List[Dict] = []
    for wf in WORKFLOWS:
        ran = [e for e in wf['engines'] if _engine_ran(report, e)]
        missing = [e for e in wf['engines'] if e not in ran]
        status = 'covered' if not missing else ('partial' if ran else 'not_run')
        entry = copy.deepcopy(wf)
        entry.update({
            'status': status,
            'ran': ran,
            'missing': missing,
            'optional_ran': [e for e in wf.get('optional', [])
                             if _engine_ran(report, e)],
        })
        out.append(entry)
    return out


def available(*, detectors: Optional[Dict] = None) -> Dict[str, bool]:
    """Which externally-gated engines are installed (the rest are built-in and
    always available). ``detectors`` maps an engine name → a probe callable to
    override the default ``features`` probes in tests."""
    probes = {'bbot': has_bbot, 'lift': has_lift,
              'pdf-text': has_pdf_text, 'ocr': has_ocr}
    if detectors:
        probes.update(detectors)
    return {name: bool(fn()) for name, fn in probes.items()}


def summary(report: Optional[Dict] = None) -> Dict:
    """Roll-up counts for the catalog. With a ``report``, counts coverage
    (covered/partial/not_run); without one, just the catalog size."""
    total = len(WORKFLOWS)
    if not isinstance(report, dict):
        return {'total': total, 'covered': 0, 'partial': 0, 'not_run': 0}
    assessed = assess(report)
    counts = {'covered': 0, 'partial': 0, 'not_run': 0}
    for wf in assessed:
        counts[wf['status']] += 1
    return {'total': total, **counts}
