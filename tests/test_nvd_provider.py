"""NVD enrichment provider (core/nvd_provider.py) — pure parsing, no network.

The network is injected (``get=``), so these exercise the real NVD 2.0 response
shape (CVSS v3.1/v3.0/v2 precedence, English summary, published date) and the
degrade paths, fully offline.
"""

import json

from core import nvd_provider as nvd


def _resp(cve_id='CVE-2020-11022', *, score=6.1, severity='MEDIUM',
          metric='cvssMetricV31', published='2020-04-29T20:15Z', desc='jQuery XSS',
          weaknesses=None):
    cve = {
        'id': cve_id,
        'published': published,
        'descriptions': [{'lang': 'es', 'value': 'otra'},
                         {'lang': 'en', 'value': desc}],
        'metrics': {metric: [{'cvssData': {'baseScore': score,
                                           'baseSeverity': severity}}]},
    }
    if weaknesses is not None:
        cve['weaknesses'] = weaknesses
    return json.dumps({'vulnerabilities': [{'cve': cve}]})


def test_enrich_parses_cvss_v31_summary_and_date():
    d = nvd.enrich('CVE-2020-11022', get=lambda url: _resp())
    assert d['cvss'] == 6.1 and d['severity'] == 'Medium'
    assert d['published'] == '2020-04-29'      # date part only
    assert d['summary'] == 'jQuery XSS' and d['source'] == 'nvd'


def test_enrich_extracts_cwe_and_skips_placeholders():
    # NVD weaknesses → concrete CWE ids; placeholders (NVD-CWE-noinfo) are skipped,
    # and duplicates across primary/secondary entries are de-duplicated.
    weaknesses = [
        {'type': 'Primary', 'description': [{'lang': 'en', 'value': 'CWE-79'}]},
        {'type': 'Secondary', 'description': [{'lang': 'en', 'value': 'CWE-79'}]},
        {'type': 'Secondary', 'description': [{'lang': 'en', 'value': 'NVD-CWE-noinfo'}]},
    ]
    d = nvd.enrich('CVE-2020-11022', get=lambda url: _resp(weaknesses=weaknesses))
    assert d['cwe'] == ['CWE-79']


def test_enrich_cwe_empty_when_absent():
    d = nvd.enrich('CVE-2020-11022', get=lambda url: _resp())
    assert d['cwe'] == []


def test_enrich_high_severity_bucket():
    d = nvd.enrich('CVE-2021-23337', get=lambda url: _resp(
        'CVE-2021-23337', score=7.2, severity='HIGH'))
    assert d['severity'] == 'High' and d['cvss'] == 7.2


def test_enrich_falls_back_to_score_when_label_missing():
    # No baseSeverity → bucket from the numeric score (>=4 → Medium).
    resp = json.dumps({'vulnerabilities': [{'cve': {
        'id': 'CVE-1', 'published': '2022-01-01T00:00Z',
        'descriptions': [{'lang': 'en', 'value': 'x'}],
        'metrics': {'cvssMetricV2': [{'cvssData': {'baseScore': 5.0}}]}}}]})
    d = nvd.enrich('CVE-1', get=lambda url: resp)
    assert d['severity'] == 'Medium' and d['cvss'] == 5.0


def test_enrich_skips_non_cve_ids():
    # GHSA-only advisories have no NVD record → no query, returns None.
    called = []
    assert nvd.enrich('GHSA-xxxx', get=lambda url: called.append(url) or '') is None
    assert called == []


def test_enrich_degrades_on_empty_or_malformed():
    assert nvd.enrich('CVE-2020-11022', get=lambda url: '') is None
    assert nvd.enrich('CVE-2020-11022', get=lambda url: 'not json') is None
    # A response for a different CVE id is not mistaken for this one.
    assert nvd.enrich('CVE-2020-11022',
                      get=lambda url: _resp('CVE-9999-0000')) is None


def test_parse_prefers_v31_over_v2():
    doc = {'vulnerabilities': [{'cve': {
        'id': 'CVE-2', 'published': '2021-05-05T00:00Z',
        'descriptions': [{'lang': 'en', 'value': 'y'}],
        'metrics': {
            'cvssMetricV2': [{'cvssData': {'baseScore': 4.3}, 'baseSeverity': 'MEDIUM'}],
            'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}],
        }}}]}
    d = nvd._parse_nvd(json.dumps(doc), 'CVE-2')
    assert d['cvss'] == 9.8 and d['severity'] == 'High'   # CRITICAL → High bucket
