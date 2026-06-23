"""core/compliance.py
OWASP Top 10 (2021) + CWE compliance mapping (EPIC 16 wave 2, A3).

A pure, offline derive-on-read layer that classifies each finding into an OWASP
Top 10 2021 category and the relevant CWE(s), then rolls findings up per category
so a report can show coverage *and* the clean categories. Mirrors the
``finding_knowledge`` catalog pattern (per-category default + keyword rule
specifics) — one source of truth for the mapping, no schema change, no new data.

The mapping is deliberately conservative: every canonical finding category
(``finding_fingerprint.CATEGORIES`` + ``transport``) has a default OWASP/CWE, and
generic ``vuln`` findings are refined by a keyword rule map (sqli → A03/CWE-89,
ssrf → A10/CWE-918, …). A ``vuln`` finding with no recognized subtype stays
``unmapped`` rather than being force-fit into a category.
"""

from typing import Dict, List, Optional

from core.severity import RANK as _SEVERITY_RANK  # platform severity ranking SSOT

# OWASP Top 10 2021, in canonical order (id → name). Kept as an ordered tuple so a
# report can list every category — including the ones with zero findings (clean).
OWASP_TOP10 = (
    ('A01:2021', 'Broken Access Control'),
    ('A02:2021', 'Cryptographic Failures'),
    ('A03:2021', 'Injection'),
    ('A04:2021', 'Insecure Design'),
    ('A05:2021', 'Security Misconfiguration'),
    ('A06:2021', 'Vulnerable and Outdated Components'),
    ('A07:2021', 'Identification and Authentication Failures'),
    ('A08:2021', 'Software and Data Integrity Failures'),
    ('A09:2021', 'Security Logging and Monitoring Failures'),
    ('A10:2021', 'Server-Side Request Forgery (SSRF)'),
)
_OWASP_NAMES = dict(OWASP_TOP10)

# Canonical finding category → default OWASP category + CWE(s).
_CATEGORY_MAP: Dict[str, Dict] = {
    'header':     {'owasp': 'A05:2021', 'cwe': ['CWE-693']},
    'cookie':     {'owasp': 'A05:2021', 'cwe': ['CWE-614', 'CWE-1004']},
    'secret':     {'owasp': 'A07:2021', 'cwe': ['CWE-798']},
    'sourcemap':  {'owasp': 'A05:2021', 'cwe': ['CWE-540']},
    'graphql':    {'owasp': 'A05:2021', 'cwe': ['CWE-200']},
    'dns':        {'owasp': 'A05:2021', 'cwe': ['CWE-16']},
    'dependency': {'owasp': 'A06:2021', 'cwe': ['CWE-1104', 'CWE-1035']},
    'tech':       {'owasp': 'A05:2021', 'cwe': ['CWE-200']},
    'endpoint':   {'owasp': 'A01:2021', 'cwe': ['CWE-200']},
    'takeover':   {'owasp': 'A05:2021', 'cwe': ['CWE-284']},
    'transport':  {'owasp': 'A02:2021', 'cwe': ['CWE-319']},
    'iac':        {'owasp': 'A05:2021', 'cwe': ['CWE-1032', 'CWE-16']},
    # Generic vuln: resolved by the rule map below; unmapped otherwise.
    'vuln':       {'owasp': None, 'cwe': []},
}

# Keyword (matched in "<rule_id> <title>" lowercased) → OWASP/CWE override that
# replaces the category default. First match wins. Refines generic ``vuln``
# findings into their real class (and re-classes transport-style titles).
_RULE_MAP = (
    ('sqli', {'owasp': 'A03:2021', 'cwe': ['CWE-89']}),
    ('sql injection', {'owasp': 'A03:2021', 'cwe': ['CWE-89']}),
    ('cross-site scripting', {'owasp': 'A03:2021', 'cwe': ['CWE-79']}),
    ('xss', {'owasp': 'A03:2021', 'cwe': ['CWE-79']}),
    ('command injection', {'owasp': 'A03:2021', 'cwe': ['CWE-77']}),
    ('remote code', {'owasp': 'A03:2021', 'cwe': ['CWE-94']}),
    ('rce', {'owasp': 'A03:2021', 'cwe': ['CWE-94']}),
    ('server-side request', {'owasp': 'A10:2021', 'cwe': ['CWE-918']}),
    ('ssrf', {'owasp': 'A10:2021', 'cwe': ['CWE-918']}),
    ('insecure direct object', {'owasp': 'A01:2021', 'cwe': ['CWE-639']}),
    ('idor', {'owasp': 'A01:2021', 'cwe': ['CWE-639']}),
    ('path traversal', {'owasp': 'A01:2021', 'cwe': ['CWE-22']}),
    ('directory traversal', {'owasp': 'A01:2021', 'cwe': ['CWE-22']}),
    ('local file inclusion', {'owasp': 'A01:2021', 'cwe': ['CWE-22']}),
    ('open redirect', {'owasp': 'A01:2021', 'cwe': ['CWE-601']}),
    ('csrf', {'owasp': 'A01:2021', 'cwe': ['CWE-352']}),
    ('plain http', {'owasp': 'A02:2021', 'cwe': ['CWE-319']}),
    # A CVE-identified finding (findings_adapter canonicalizes these to
    # category='vuln', rule_id='cve-…') is the textbook A06 "Vulnerable and
    # Outdated Components" case. Kept LAST so a CVE that is *also* a recognized
    # class (e.g. an XSS CVE) still maps to its specific class above; only an
    # otherwise-unclassified CVE falls here instead of "unmapped".
    ('cve-', {'owasp': 'A06:2021', 'cwe': ['CWE-1395']}),
)

# Auditor-friendly framework crosswalk (EPIC NEXT F6). Beyond OWASP/CWE, an
# auditor wants the finding mapped to the control frameworks they certify against.
# This is a *derive over the OWASP class* — one SSOT, no second classification
# system: each OWASP Top-10 2021 category maps to a representative control in PCI
# DSS v4.0, ISO/IEC 27001:2022 (Annex A), NIST CSF 2.0 and SOC 2 (Trust Services
# Criteria). Representative references for triage/coverage — not a substitute for a
# formal audit.
AUDITOR_FRAMEWORKS = ('pci_dss', 'iso_27001', 'nist_csf', 'soc2')
FRAMEWORK_LABELS = {
    'pci_dss': 'PCI DSS v4.0', 'iso_27001': 'ISO/IEC 27001:2022',
    'nist_csf': 'NIST CSF 2.0', 'soc2': 'SOC 2 (TSC)',
}
_OWASP_FRAMEWORKS: Dict[str, Dict[str, str]] = {
    'A01:2021': {'pci_dss': '7.2', 'iso_27001': 'A.5.15', 'nist_csf': 'PR.AA',
                 'soc2': 'CC6.1'},
    'A02:2021': {'pci_dss': '3.5, 4.2', 'iso_27001': 'A.8.24', 'nist_csf': 'PR.DS',
                 'soc2': 'CC6.7'},
    'A03:2021': {'pci_dss': '6.2.4', 'iso_27001': 'A.8.28', 'nist_csf': 'PR.PS',
                 'soc2': 'CC8.1'},
    'A04:2021': {'pci_dss': '6.2', 'iso_27001': 'A.8.25', 'nist_csf': 'PR.PS',
                 'soc2': 'CC8.1'},
    'A05:2021': {'pci_dss': '2.2', 'iso_27001': 'A.8.9', 'nist_csf': 'PR.PS',
                 'soc2': 'CC7.1'},
    'A06:2021': {'pci_dss': '6.3.3', 'iso_27001': 'A.8.8', 'nist_csf': 'ID.RA',
                 'soc2': 'CC7.1'},
    'A07:2021': {'pci_dss': '8.3', 'iso_27001': 'A.5.17', 'nist_csf': 'PR.AA',
                 'soc2': 'CC6.1'},
    'A08:2021': {'pci_dss': '6.4.3', 'iso_27001': 'A.8.32', 'nist_csf': 'PR.DS',
                 'soc2': 'CC8.1'},
    'A09:2021': {'pci_dss': '10.2', 'iso_27001': 'A.8.15', 'nist_csf': 'DE.CM',
                 'soc2': 'CC7.2'},
    'A10:2021': {'pci_dss': '6.2.4', 'iso_27001': 'A.8.23', 'nist_csf': 'PR.IR',
                 'soc2': 'CC6.6'},
}


def frameworks_for(owasp: Optional[str]) -> Dict[str, str]:
    """Auditor-framework controls for an OWASP category id (``{}`` if unmapped)."""
    return dict(_OWASP_FRAMEWORKS.get(owasp or '', {}))


def classify(category: str, rule_id: str = '', title: str = '') -> Dict:
    """Resolve ``{owasp, owasp_name, cwe, frameworks}`` for a finding (pure).

    A keyword rule match (sqli / ssrf / …) wins over the category default; an
    unmapped finding returns ``owasp=None`` (so the caller can surface it
    separately rather than mis-classify it). ``frameworks`` is the auditor
    crosswalk (PCI/ISO/NIST/SOC2) derived from the OWASP class — empty for an
    unmapped finding (F6)."""
    cat = str(category or '').strip().lower()
    base = dict(_CATEGORY_MAP.get(cat, {'owasp': None, 'cwe': []}))
    hay = f'{str(rule_id or "").lower()} {str(title or "").lower()}'
    for keyword, override in _RULE_MAP:
        if keyword in hay:
            base = dict(override)
            break
    owasp = base.get('owasp')
    return {'owasp': owasp, 'owasp_name': _OWASP_NAMES.get(owasp, ''),
            'cwe': list(base.get('cwe') or []), 'frameworks': frameworks_for(owasp)}


def build_compliance(findings: Optional[List[Dict]]) -> Dict:
    """Roll findings up against the OWASP Top 10 (pure, offline).

    Returns ``{by_owasp, unmapped, summary}``:
      * ``by_owasp`` — every Top-10 category (in order), each
        ``{id, name, count, severities, cwe, findings}``; ``count == 0`` means the
        category is clean (no current findings map to it).
      * ``unmapped`` — findings with no confident OWASP class (generic vuln
        subtypes we don't recognize), so they are visible rather than mis-filed.
      * ``summary`` — ``{total_findings, categories_with_findings,
        worst_severity, unmapped}``.
    """
    buckets: Dict[str, Dict] = {
        oid: {'id': oid, 'name': name, 'count': 0, 'severities': {},
              'cwe': set(), 'findings': []}
        for oid, name in OWASP_TOP10}
    unmapped: List[Dict] = []
    worst = -1

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        cls = classify(f.get('category', ''), f.get('rule_id', ''),
                       f.get('title', ''))
        sev = str(f.get('severity') or 'info').strip().lower()
        worst = max(worst, _SEVERITY_RANK.get(sev, 0))
        row = {'id': f.get('id'), 'title': f.get('title', ''),
               'severity': sev, 'cwe': cls['cwe'],
               'category': str(f.get('category') or '')}
        owasp = cls['owasp']
        if owasp not in buckets:
            unmapped.append(row)
            continue
        b = buckets[owasp]
        b['count'] += 1
        b['severities'][sev] = b['severities'].get(sev, 0) + 1
        b['cwe'].update(cls['cwe'])
        b['findings'].append(row)

    by_owasp = []
    for oid, _ in OWASP_TOP10:
        b = buckets[oid]
        b['cwe'] = sorted(b['cwe'])
        b['frameworks'] = frameworks_for(oid)   # F6: auditor crosswalk per category
        by_owasp.append(b)

    total = sum(b['count'] for b in by_owasp) + len(unmapped)
    worst_label = next((s for s, r in _SEVERITY_RANK.items() if r == worst), '')
    summary = {
        'total_findings': total,
        'categories_with_findings': sum(1 for b in by_owasp if b['count']),
        'worst_severity': worst_label,
        'unmapped': len(unmapped),
    }
    return {'by_owasp': by_owasp, 'unmapped': unmapped, 'summary': summary}


def load_compliance(project: str, store=None) -> Dict:
    """Thin reader: build the compliance roll-up from a project's active findings
    (current posture — triaged/inactive excluded). ``store`` is injectable for
    tests; defaults to the shared ``FindingsStore``."""
    if store is None:
        from core.findings_store import FindingsStore
        store = FindingsStore()
    return build_compliance(store.active_findings(project))
