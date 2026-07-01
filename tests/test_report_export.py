"""CSV export of ASM data (core/report_export.py) — pure, offline.

Parsed back with csv.reader so assertions are independent of the line
terminator / quoting details that csv handles internally.
"""

import csv
import io
import json

from core import report_export as rx


def _parse(text):
    return list(csv.reader(io.StringIO(text)))


# ── findings_csv ──────────────────────────────────────────────────────────────

def test_findings_csv_header_and_row():
    rows = [{'project': 'a.com', 'severity': 'high', 'status': 'OPEN',
             'category': 'header', 'title': 'Weak CSP', 'rule_id': 'csp',
             'first_seen_at': '2026-01-01', 'last_seen_at': '2026-02-01',
             'id': 'abc123'}]
    table = _parse(rx.findings_csv(rows))
    assert table[0] == ['Project', 'Severity', 'Status', 'Category', 'Title',
                        'Rule', 'Description', 'Impact', 'Remediation',
                        'Evidence Artifacts', 'KEV', 'EPSS', 'EPSS %ile',
                        'First seen', 'Last seen', 'ID']
    row = table[1]
    assert row[rx_idx('Project')] == 'a.com'
    assert row[rx_idx('Title')] == 'Weak CSP'
    assert row[rx_idx('ID')] == 'abc123'
    # F-O3: knowledge columns filled from the catalog (csp rule specific).
    assert row[rx_idx('Remediation')]            # non-empty
    assert 'Content-Security-Policy' in row[rx_idx('Remediation')]


def test_findings_csv_uses_producer_remediation():
    # Explicit evidence remediation wins over the catalog in the export.
    rows = [{'category': 'vuln', 'title': 'X', 'severity': 'high',
             'evidence': {'remediation': 'Upgrade to 2.0'}}]
    table = _parse(rx.findings_csv(rows))
    assert table[1][rx_idx('Remediation')] == 'Upgrade to 2.0'


def test_findings_csv_exports_evidence_refs():
    rows = [{'title': 'Weak CSP', 'severity': 'high',
             'evidence': {'evidence_refs': [{
                 'artifact_id': 'sha256:abcdef1234567890',
                 'path': 'recon/recon.json',
                 'phase': 'recon',
             }]}}]
    table = _parse(rx.findings_csv(rows))

    assert table[1][rx_idx('Evidence Artifacts')] == (
        'recon:recon/recon.json#abcdef123456')


def test_findings_csv_missing_keys_become_blank():
    table = _parse(rx.findings_csv([{'title': 'X'}]))
    assert table[1][table[0].index('Title')] == 'X'
    assert table[1][table[0].index('Project')] == ''


def test_findings_csv_quotes_commas_and_quotes():
    rows = [{'title': 'a, b "c"', 'severity': 'low'}]
    out = rx.findings_csv(rows)
    # Round-trips cleanly despite the comma + embedded quotes.
    assert _parse(out)[1][rx_idx('Title')] == 'a, b "c"'


def test_findings_csv_empty_is_header_only():
    table = _parse(rx.findings_csv([]))
    assert len(table) == 1 and table[0][0] == 'Project'
    assert _parse(rx.findings_csv(None))[0][0] == 'Project'


# ── assets_csv ────────────────────────────────────────────────────────────────

def test_assets_csv_header_and_row():
    rows = [{'project': 'x.com', 'type': 'subdomain', 'value': 'api.x.com',
             'label': 'api.x.com', 'status': 'ACTIVE',
             'first_seen_at': '2026-01-01', 'last_seen_at': '2026-02-01',
             'id': 'abc123'}]
    table = _parse(rx.assets_csv(rows))
    assert table[0] == ['Project', 'Type', 'Value', 'Label', 'Status',
                        'First seen', 'Last seen', 'ID']
    assert table[1] == ['x.com', 'subdomain', 'api.x.com', 'api.x.com', 'ACTIVE',
                        '2026-01-01', '2026-02-01', 'abc123']


def test_assets_csv_empty_is_header_only():
    assert _parse(rx.assets_csv([]))[0][0] == 'Project'
    assert _parse(rx.assets_csv(None))[0][0] == 'Project'


# ── missions_csv ──────────────────────────────────────────────────────────────

def test_missions_csv_header_and_row_from_overview_dict():
    overview = {'missions': [{
        'mission_id': 'mission-abc', 'project': 'shop.com',
        'objective': 'Review', 'status': 'completed',
        'last_run_id': 'mrun-1', 'last_run_status': 'completed',
        'client_facing': 3, 'updated_at': '2026-02-01T10:00:00'}]}
    table = _parse(rx.missions_csv(overview))
    assert table[0] == ['Mission ID', 'Project', 'Objective', 'Status',
                        'Last Run', 'Last Run Status', 'Client-facing', 'Updated']
    assert table[1] == ['mission-abc', 'shop.com', 'Review', 'completed',
                        'mrun-1', 'completed', '3', '2026-02-01T10:00:00']


def test_missions_csv_accepts_bare_list_and_empty():
    assert _parse(rx.missions_csv([]))[0][0] == 'Mission ID'
    assert _parse(rx.missions_csv({'missions': []}))[0][0] == 'Mission ID'
    table = _parse(rx.missions_csv([{'mission_id': 'm1', 'project': 'p'}]))
    assert table[1][0] == 'm1' and table[1][1] == 'p'


# ── timeline_csv ──────────────────────────────────────────────────────────────

def test_timeline_csv_header_and_row():
    rows = [{'at': '2026-06-14T01:00:00', 'scan_id': '20260614_010000',
             'severity': 'high', 'section': 'subdomains', 'type': 'takeover',
             'title': 'api.x.com ⚠ takeover'}]
    table = _parse(rx.timeline_csv(rows))
    assert table[0] == ['When', 'Scan', 'Severity', 'Section', 'Event', 'Detail']
    assert table[1] == ['2026-06-14T01:00:00', '20260614_010000', 'high',
                        'subdomains', 'takeover', 'api.x.com ⚠ takeover']


def test_timeline_csv_empty_is_header_only():
    assert _parse(rx.timeline_csv([]))[0][0] == 'When'
    assert _parse(rx.timeline_csv(None))[0][0] == 'When'


# ── history_csv (EPIC 4 — per-scan risk history) ────────────────────────────────

def test_history_csv_header_and_row():
    series = [{'at': '2026-06-13', 'scan_id': 's1', 'risk_level': 'Low',
               'risk_score': 4, 'attack_surface': 2, 'secrets': 0,
               'high': 0, 'medium': 1}]
    table = _parse(rx.history_csv(series))
    assert table[0] == ['When', 'Scan', 'Risk', 'Risk Score', 'Attack Surface',
                        'Secrets', 'High', 'Medium']
    assert table[1] == ['2026-06-13', 's1', 'Low', '4', '2', '0', '0', '1']


def test_history_csv_empty_is_header_only():
    assert _parse(rx.history_csv([]))[0][0] == 'When'
    assert _parse(rx.history_csv(None))[0][0] == 'When'


# ── intelligence_csv (EPIC 7 — priority-ranked findings) ────────────────────────

def test_intelligence_csv_header_and_row():
    items = [{'priority': 73, 'confidence': 85, 'confidence_band': 'high',
              'severity': 'high', 'category': 'graphql',
              'title': 'GraphQL introspection', 'id': 'f-1',
              'explanation': {'description': 'desc', 'impact': 'imp',
                              'remediation': 'rem'}}]
    table = _parse(rx.intelligence_csv(items))
    assert table[0] == ['Priority', 'Confidence', 'Confidence Band', 'Severity',
                        'Category', 'Title', 'Description', 'Impact',
                        'Remediation', 'ID']
    assert table[1] == ['73', '85', 'high', 'high', 'graphql',
                        'GraphQL introspection', 'desc', 'imp', 'rem', 'f-1']


def test_intelligence_csv_flattens_missing_explanation():
    # No 'explanation' key → the three derived columns are blank, not an error.
    table = _parse(rx.intelligence_csv([{'priority': 5, 'title': 't'}]))
    row = dict(zip(table[0], table[1]))
    assert row['Title'] == 't' and row['Description'] == ''


def test_intelligence_csv_empty_is_header_only():
    assert _parse(rx.intelligence_csv([]))[0][0] == 'Priority'
    assert _parse(rx.intelligence_csv(None))[0][0] == 'Priority'


# ── criticality_csv (EPIC 9 — assets ranked by criticality) ─────────────────────

def test_criticality_csv_header_and_flattened_factors():
    items = [{'criticality': 65, 'band': 'medium', 'type': 'domain',
              'value': 'x.com', 'id': 'a-1',
              'factors': [{'factor': 'Тип актива: domain', 'points': 40},
                          {'factor': 'Публично доступен (2xx)', 'points': 5}]}]
    table = _parse(rx.criticality_csv(items))
    assert table[0] == ['Criticality', 'Band', 'Type', 'Value', 'Factors', 'ID']
    row = dict(zip(table[0], table[1]))
    assert row['Criticality'] == '65' and row['Value'] == 'x.com'
    assert 'Тип актива: domain (+40)' in row['Factors']
    assert 'Публично доступен (2xx) (+5)' in row['Factors']


def test_criticality_csv_empty_is_header_only():
    assert _parse(rx.criticality_csv([]))[0][0] == 'Criticality'
    assert _parse(rx.criticality_csv(None))[0][0] == 'Criticality'


# ── exposure_csv (likelihood axis — assets ranked by exposure) ──────────────────

def test_exposure_csv_header_and_flattened_factors():
    items = [{'exposure': 55, 'band': 'medium', 'type': 'subdomain',
              'value': 'a.x.com', 'id': 'a-1',
              'factors': [{'factor': 'Публично доступен (2xx)', 'points': 20},
                          {'factor': 'Открытые находки: 1 (worst critical)',
                           'points': 30}]}]
    table = _parse(rx.exposure_csv(items))
    assert table[0] == ['Exposure', 'Band', 'Type', 'Value', 'Factors', 'ID']
    row = dict(zip(table[0], table[1]))
    assert row['Exposure'] == '55' and row['Value'] == 'a.x.com'
    assert 'Публично доступен (2xx) (+20)' in row['Factors']


def test_exposure_csv_empty_is_header_only():
    assert _parse(rx.exposure_csv([]))[0][0] == 'Exposure'
    assert _parse(rx.exposure_csv(None))[0][0] == 'Exposure'


# ── attack_paths_csv (EPIC 11 — lateral attack paths) ───────────────────────────

def test_attack_paths_csv_header_and_flattened_targets():
    paths = [{'score': 55, 'band': 'medium', 'entry': 'api.x.com',
              'entry_severity': 'high', 'pivot_type': 'ip',
              'pivot_node': '1.2.3.4', 'size': 3,
              'targets': ['a.x.com', 'b.x.com'], 'critical_targets': 1}]
    table = _parse(rx.attack_paths_csv(paths))
    assert table[0] == ['Score', 'Band', 'Entry', 'Entry Severity', 'Pivot Type',
                        'Pivot Node', 'Cluster Size', 'Targets', 'Critical Targets']
    row = dict(zip(table[0], table[1]))
    assert row['Score'] == '55' and row['Entry'] == 'api.x.com'
    assert row['Targets'] == 'a.x.com; b.x.com'
    assert row['Critical Targets'] == '1'


def test_attack_paths_csv_empty_is_header_only():
    assert _parse(rx.attack_paths_csv([]))[0][0] == 'Score'
    assert _parse(rx.attack_paths_csv(None))[0][0] == 'Score'


# ── findings_sarif (EPIC 16 F1 — SARIF 2.1.0) ───────────────────────────────────

def _sarif(findings, **kw):
    return json.loads(rx.findings_sarif(findings, **kw))


def test_sarif_skeleton_and_tool():
    doc = _sarif([], tool_version='1.2.3')
    assert doc['version'] == '2.1.0'
    assert doc['$schema'].endswith('sarif-2.1.0.json')
    driver = doc['runs'][0]['tool']['driver']
    assert driver['name'] == 'Advanced Site Analyzer'
    assert driver['version'] == '1.2.3'
    assert doc['runs'][0]['results'] == [] and driver['rules'] == []


def test_sarif_result_and_rule_mapping():
    findings = [
        {'category': 'secret', 'rule_id': 'aws-key', 'severity': 'critical',
         'title': 'Leaked secret: AWS', 'status': 'OPEN',
         'first_seen_at': '2026-01-01',
         'evidence': {'location': 'https://x.com/app.js'}},
        {'category': 'header', 'rule_id': '', 'severity': 'medium',
         'title': 'Missing CSP', 'status': 'OPEN', 'evidence': {}},
    ]
    doc = _sarif(findings)
    results = doc['runs'][0]['results']
    rules = {r['id']: r for r in doc['runs'][0]['tool']['driver']['rules']}
    # rule ids: rule_id when present, else category.
    assert 'aws-key' in rules and 'header' in rules
    # severity -> level + numeric security-severity on the rule.
    crit = next(r for r in results if r['ruleId'] == 'aws-key')
    assert crit['level'] == 'error'
    assert rules['aws-key']['properties']['security-severity'] == '9.5'
    assert crit['locations'][0]['physicalLocation']['artifactLocation']['uri'] \
        == 'https://x.com/app.js'
    med = next(r for r in results if r['ruleId'] == 'header')
    assert med['level'] == 'warning'
    # no evidence.location -> no locations key.
    assert 'locations' not in med


def test_sarif_dedups_rules_and_carries_severity_property():
    findings = [
        {'category': 'cookie', 'rule_id': 'samesite', 'severity': 'low',
         'title': 'A', 'status': 'OPEN', 'evidence': {}},
        {'category': 'cookie', 'rule_id': 'samesite', 'severity': 'low',
         'title': 'B', 'status': 'OPEN', 'evidence': {}},
    ]
    doc = _sarif(findings)
    rules = doc['runs'][0]['tool']['driver']['rules']
    assert sum(1 for r in rules if r['id'] == 'samesite') == 1   # deduped
    results = doc['runs'][0]['results']
    assert len(results) == 2 and all(r['level'] == 'note' for r in results)
    assert results[0]['properties']['severity'] == 'low'


def test_sarif_rule_tags_carry_cwe_and_owasp_taxonomy():
    # The rule tags carry the CWE taxonomy (external/cwe/cwe-NNN, GitHub code
    # scanning's convention) and OWASP class from the compliance SSOT, so the SARIF
    # matches the compliance report. A secret → A07 / CWE-798; a CVE finding → A06.
    findings = [
        {'category': 'secret', 'rule_id': 'aws-key', 'severity': 'critical',
         'title': 'Leaked secret: AWS', 'status': 'OPEN', 'evidence': {}},
        {'category': 'vuln', 'rule_id': 'cve-2020-11022', 'severity': 'high',
         'title': 'jQuery vulnerable', 'status': 'OPEN', 'evidence': {}},
    ]
    rules = {r['id']: r for r in
             _sarif(findings)['runs'][0]['tool']['driver']['rules']}
    sec_tags = rules['aws-key']['properties']['tags']
    assert 'secret' in sec_tags
    assert 'external/cwe/cwe-798' in sec_tags
    assert 'OWASP:A07:2021' in sec_tags
    cve_tags = rules['cve-2020-11022']['properties']['tags']
    assert 'external/cwe/cwe-1395' in cve_tags and 'OWASP:A06:2021' in cve_tags
    # F6: the auditor-framework crosswalk rides along (A07 secret controls).
    assert 'PCI-DSS:8.3' in sec_tags and 'ISO-27001:A.5.17' in sec_tags
    assert 'NIST-CSF:PR.AA' in sec_tags and 'SOC2:CC6.1' in sec_tags


def test_sarif_tags_prefer_explicit_finding_cwe():
    # A finding carrying an explicit CWE in evidence (e.g. NVD's per-CVE weakness)
    # surfaces that precise tag alongside the generic category-mapping one.
    findings = [
        {'category': 'vuln', 'rule_id': 'cve-2020-11022', 'severity': 'high',
         'title': 'jQuery vulnerable', 'status': 'OPEN',
         'evidence': {'cwe': ['CWE-79']}},
    ]
    rules = {r['id']: r for r in
             _sarif(findings)['runs'][0]['tool']['driver']['rules']}
    tags = rules['cve-2020-11022']['properties']['tags']
    assert 'external/cwe/cwe-79' in tags          # explicit NVD weakness
    assert 'external/cwe/cwe-1395' in tags         # generic component default too
    assert tags.count('external/cwe/cwe-79') == 1  # de-duplicated


def test_sarif_none_is_valid_empty_run():
    doc = _sarif(None)
    assert doc['runs'][0]['results'] == []


# ── report_markdown (EPIC 16 F2) ────────────────────────────────────────────────

def test_report_markdown_renders_verdict_and_sections():
    report = {
        'domain': 'acme.com', 'started_at': '2026-06-20T10:00:00',
        'finished_at': '2026-06-20T10:05:00',
        'summary': {
            'risk_level': 'High', 'risk_100': 72,
            'metrics': {'high': 3},
            'key_findings': ['1 leaked secret', '3 high vulns'],
            'risk_factors': [{'factor': 'Leaked secrets', 'points': 5,
                              'detail': '1 plausible'}],
            'recommendations': ['Rotate the AWS key', 'Add CSP'],
        }}
    md = rx.report_markdown(report)
    assert md.startswith('# Security Report — acme.com')
    assert 'Risk verdict: **High** (72/100)' in md
    assert '## Key findings' in md and '- 1 leaked secret' in md
    assert 'Leaked secrets: +5 — 1 plausible' in md           # score breakdown
    assert '## Recommendations' in md and '- Rotate the AWS key' in md


def test_report_markdown_prefers_executive_summary():
    report = {
        'domain': 'acme.com',
        'summary': {'risk_level': 'Clean', 'risk_100': 0},
        'executive_summary': {
            'risk_level': 'Critical',
            'risk_score': 95,
            'key_findings': ['takeover candidate'],
        },
    }
    md = rx.report_markdown(report)
    assert 'Risk verdict: **Critical** (95/100)' in md
    assert '- takeover candidate' in md


def test_report_markdown_renders_warnings_section():
    report = {
        'domain': 'acme.com',
        'executive_summary': {'risk_level': 'Low', 'risk_score': 12},
        'warnings': [{
            'stage': 'evidence',
            'message': 'Evidence manifest could not be written',
            'error': 'disk full',
        }],
    }
    md = rx.report_markdown(report)
    assert '## Warnings' in md
    assert '- evidence: Evidence manifest could not be written — disk full' in md


def test_report_markdown_empty_is_minimal_header():
    md = rx.report_markdown({})
    assert md.startswith('# Security Report — target')
    assert 'Risk verdict: **Clean**' in md
    # no spurious sections when summary is empty
    assert '## Key findings' not in md


def test_report_markdown_handles_non_dict():
    assert rx.report_markdown(None).startswith('# Security Report')


# ── compliance_markdown (EPIC 16 wave 2 A3) ─────────────────────────────────────

def test_compliance_markdown_renders_table_and_sections():
    findings = [
        {'id': 'h', 'category': 'header', 'title': 'Missing HSTS',
         'severity': 'medium'},
        {'id': 'q', 'category': 'vuln', 'rule_id': 'sqli',
         'title': 'SQL injection', 'severity': 'high'},
    ]
    md = rx.compliance_markdown(findings)
    assert md.startswith('# OWASP Top 10 (2021) Compliance Report')
    assert '| OWASP category | Status |' in md
    assert 'A03:2021 Injection' in md and 'CWE-89' in md
    assert '⚠️ findings' in md and '✅ OK' in md       # both a hit and clean rows
    assert '## A05:2021 Security Misconfiguration (1)' in md
    assert '[high] SQL injection (CWE-89)' in md


def test_compliance_markdown_empty_is_all_clean():
    md = rx.compliance_markdown([])
    assert 'Active findings: 0' in md
    assert '⚠️ findings' not in md and md.count('✅ OK') == 10


def test_compliance_markdown_unmapped_section():
    md = rx.compliance_markdown([{'id': 'm', 'category': 'vuln', 'rule_id': 'x',
                                  'title': 'Mystery', 'severity': 'low'}])
    assert '## Unmapped (review)' in md and 'Mystery' in md


def test_compliance_markdown_framework_crosswalk():
    # F6: a category with findings appears in the auditor crosswalk table with its
    # PCI/ISO/NIST/SOC2 controls; an all-clean report has no crosswalk.
    md = rx.compliance_markdown([{'id': 'q', 'category': 'vuln', 'rule_id': 'sqli',
                                  'title': 'SQL injection', 'severity': 'high'}])
    assert '## Framework crosswalk' in md
    assert 'PCI DSS v4.0' in md and 'ISO/IEC 27001:2022' in md
    assert 'NIST CSF 2.0' in md and 'SOC 2 (TSC)' in md
    assert '6.2.4' in md and 'A.8.28' in md            # A03 controls
    assert '## Framework crosswalk' not in rx.compliance_markdown([])


# ── technology_risk_csv (EPIC 15 — technology-risk items) ───────────────────────

def test_technology_risk_csv_header_and_flattened_evidence():
    items = [{'kind': 'dependency', 'name': 'jquery', 'version': '1.7.0',
              'category': 'JS dependency', 'score': 40, 'band': 'medium',
              'reason': '1 known vulnerable advisory/advisories; worst=high',
              'evidence': ['CVE-2020-11022', 'CVE-2020-11023']}]
    table = _parse(rx.technology_risk_csv(items))
    assert table[0] == ['Score', 'Band', 'Kind', 'Name', 'Version', 'Category',
                        'Reason', 'Evidence']
    row = dict(zip(table[0], table[1]))
    assert row['Score'] == '40' and row['Name'] == 'jquery'
    assert row['Evidence'] == 'CVE-2020-11022; CVE-2020-11023'


def test_technology_risk_csv_empty_is_header_only():
    assert _parse(rx.technology_risk_csv([]))[0][0] == 'Score'
    assert _parse(rx.technology_risk_csv(None))[0][0] == 'Score'


# ── accuracy_csv (MODULE 1 — scan-accuracy entities) ────────────────────────────

def test_accuracy_csv_header_and_flattened_lists():
    items = [{'entity_type': 'technology', 'label': 'nginx 1.18', 'score': 90,
              'band': 'high', 'verification': 'header',
              'source': ['header'], 'evidence': ['header:Server', 'html']}]
    table = _parse(rx.accuracy_csv(items))
    assert table[0] == ['Confidence', 'Band', 'Type', 'Entity', 'Verification',
                        'Source', 'Evidence']
    row = dict(zip(table[0], table[1]))
    assert row['Confidence'] == '90' and row['Entity'] == 'nginx 1.18'
    assert row['Source'] == 'header'
    assert row['Evidence'] == 'header:Server; html'


def test_accuracy_csv_empty_is_header_only():
    assert _parse(rx.accuracy_csv([]))[0][0] == 'Confidence'
    assert _parse(rx.accuracy_csv(None))[0][0] == 'Confidence'


# ── osint_catalog_csv (EXT-OSINT F3 — workflow coverage) ────────────────────────

def test_osint_catalog_csv_header_and_flattened_engines():
    workflows = [{
        'id': 'infrastructure-recon', 'name': 'Infrastructure Recon',
        'category': 'Digital Infrastructure', 'network': 'active',
        'status': 'partial', 'goal': 'Map the external infrastructure.',
        'engines': ['recon', 'subdomains', 'ct'], 'ran': ['recon', 'subdomains'],
        'missing': ['ct'], 'optional_ran': [], 'produces': ['assets', 'attack_surface'],
    }]
    table = _parse(rx.osint_catalog_csv(workflows))
    assert table[0] == ['Status', 'Workflow', 'Category', 'Network', 'Coverage',
                        'Goal', 'Engines Ran', 'Engines Missing', 'Optional Ran',
                        'Produces']
    row = dict(zip(table[0], table[1]))
    assert row['Status'] == 'partial' and row['Workflow'] == 'Infrastructure Recon'
    assert row['Coverage'] == '2/3'
    assert row['Engines Ran'] == 'recon; subdomains'
    assert row['Engines Missing'] == 'ct'
    assert row['Produces'] == 'assets; attack_surface'


def test_osint_catalog_csv_empty_is_header_only():
    assert _parse(rx.osint_catalog_csv([]))[0][0] == 'Status'
    assert _parse(rx.osint_catalog_csv(None))[0][0] == 'Status'


# ── evidence_integrity_csv ───────────────────────────────────────────────────

def test_evidence_integrity_csv_exports_warning_summary():
    audit = {
        'scan_id': 's1',
        'status': 'failed',
        'ok': False,
        'checked': 2,
        'missing': ['api/api_keys.json'],
        'changed': ['recon/recon.json'],
        'scan_dir': '/tmp/s1',
    }
    table = _parse(rx.evidence_integrity_csv(audit))
    row = dict(zip(table[0], table[1]))

    assert table[0] == ['Scan', 'Status', 'OK', 'Checked', 'Missing',
                        'Changed', 'Warning', 'Scan Dir']
    assert row['Scan'] == 's1'
    assert row['Missing'] == '1'
    assert row['Changed'] == '1'
    assert 'failed' in row['Warning']


# ── portfolio_csv ─────────────────────────────────────────────────────────────

def test_tool_runs_csv_from_full_dict():
    tl = {'tool_runs': [
        {'tool': 'header_audit', 'scan_id': 'tool-header_audit-1700000000',
         'at': '2026-04-01T10:00:00', 'findings': 2, 'assets': 1},
    ]}
    table = _parse(rx.tool_runs_csv(tl))
    assert table[0] == ['When', 'Tool', 'Findings', 'Assets', 'Scan ID']
    row = table[1]
    assert row[table[0].index('Tool')] == 'header_audit'
    assert row[table[0].index('Findings')] == '2'
    assert row[table[0].index('Assets')] == '1'
    assert row[table[0].index('Scan ID')] == 'tool-header_audit-1700000000'


def test_tool_runs_csv_accepts_bare_row_list():
    table = _parse(rx.tool_runs_csv([{'tool': 'cookie_audit', 'findings': 0,
                                      'assets': 3}]))
    assert table[1][table[0].index('Tool')] == 'cookie_audit'


def test_tool_runs_csv_empty():
    assert _parse(rx.tool_runs_csv({'tool_runs': []}))[0][0] == 'When'
    assert _parse(rx.tool_runs_csv(None))[0][0] == 'When'


def test_retest_runs_csv_from_full_dict_flattens_summary():
    tl = {'retest_runs': [
        {'retest_run_id': 'rt-abc', 'engagement_id': 'eng-1',
         'status': 'completed', 'created_at': '2026-07-01T10:00:00Z',
         'summary': {'total': 3, 'fixed': 1, 'open': 1, 'accepted': 0,
                     'missing': 1}},
    ]}
    table = _parse(rx.retest_runs_csv(tl))
    assert table[0] == ['When', 'Engagement', 'Status', 'Fixed', 'Open',
                        'Accepted', 'Missing', 'Total', 'Run ID']
    row = table[1]
    assert row[table[0].index('Engagement')] == 'eng-1'
    assert row[table[0].index('Fixed')] == '1'
    assert row[table[0].index('Total')] == '3'
    assert row[table[0].index('Run ID')] == 'rt-abc'


def test_retest_runs_csv_accepts_bare_list_and_empty():
    table = _parse(rx.retest_runs_csv([{'retest_run_id': 'rt-x',
                                        'engagement_id': 'eng-x',
                                        'status': 'completed', 'summary': {}}]))
    assert table[1][table[0].index('Run ID')] == 'rt-x'
    assert _parse(rx.retest_runs_csv(None))[0][0] == 'When'


def test_portfolio_csv_from_full_dict():
    portfolio = {'rows': [{'slug': 'x.com', 'url': 'https://x', 'risk_level': 'High',
                           'risk_score': 12, 'risk_delta': 50, 'attack_surface': 11,
                           'secrets': 1, 'high': 2, 'medium': 1,
                           'warning_count': 3, 'warning_stages': 'evidence, findings_sync',
                           'active_findings': 0, 'scan_count': 2,
                           'updated_at': '2026-06-14'}]}
    table = _parse(rx.portfolio_csv(portfolio))
    assert table[0][0] == 'Project' and 'Risk' in table[0]
    row = table[1]
    assert row[0] == 'x.com'
    assert row[table[0].index('Score')] == '12'
    assert row[table[0].index('Delta')] == '50'
    assert row[table[0].index('Warnings')] == '3'
    assert row[table[0].index('Warning Stages')] == 'evidence, findings_sync'


def test_portfolio_csv_accepts_bare_row_list():
    table = _parse(rx.portfolio_csv([{'slug': 'y.com', 'risk_level': 'Low'}]))
    assert table[1][0] == 'y.com'


def test_portfolio_csv_empty():
    assert _parse(rx.portfolio_csv({'rows': []}))[0][0] == 'Project'
    assert _parse(rx.portfolio_csv(None))[0][0] == 'Project'


def rx_idx(header):
    return [h for _, h in rx._FINDINGS_COLUMNS].index(header)
