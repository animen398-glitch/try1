"""CVE Intelligence orchestrator (core/cve_intel.py) — OSV + NVD + cache.

All network seams are injected (``osv_post`` / ``nvd_get``), so these exercise the
real flow — correlate → enrich → cache → findings/summary — fully offline, and pin
the caching policy (fresh hit skips network; offline reuses stale; clean library is
not pinned to a stale hit). The CVE-cache DB is the conftest-isolated tmp file.
"""

import json

from core import cve_intel
from core.cve_store import CVEStore


def _osv_resp(*cve_ids, severity='MODERATE'):
    return json.dumps({'vulns': [
        {'id': c, 'aliases': [c], 'summary': f'adv {c}', 'published': '2020-01-02',
         'database_specific': {'severity': severity}}
        for c in cve_ids]})


def _nvd_resp(cve_id, score=6.1, sev='MEDIUM'):
    return json.dumps({'vulnerabilities': [{'cve': {
        'id': cve_id, 'published': '2020-04-29T00:00Z',
        'descriptions': [{'lang': 'en', 'value': f'nvd {cve_id}'}],
        'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': score,
                                                    'baseSeverity': sev}}]}}}]})


_LIBS = [{'library': 'jquery', 'name': 'jQuery', 'version': '1.11.0'}]


def test_correlate_enriches_osv_with_nvd(tmp_path):
    store = CVEStore(tmp_path / 'c.db')
    out = cve_intel.correlate(
        _LIBS, store=store,
        osv_post=lambda url, payload: _osv_resp('CVE-2020-11022'),
        nvd_get=lambda url: _nvd_resp('CVE-2020-11022', score=6.1, sev='MEDIUM'))
    rec = out['jquery'][0]
    assert rec['cve'] == ['CVE-2020-11022']
    assert rec['cvss'] == 6.1 and rec['published'] == '2020-04-29'   # NVD authoritative
    assert rec['severity'] == 'Medium' and rec['source'] == 'osv+nvd'


def test_offline_reuses_cached_when_provider_unreachable(tmp_path):
    store = CVEStore(tmp_path / 'c.db')
    # First (online) run caches the advisory + enrichment.
    cve_intel.correlate(_LIBS, store=store,
                        osv_post=lambda u, p: _osv_resp('CVE-2020-11022'),
                        nvd_get=lambda u: _nvd_resp('CVE-2020-11022'))
    # Second run with both providers DOWN ('' = unreachable) → stale cache reused.
    out = cve_intel.correlate(_LIBS, store=store,
                              osv_post=lambda u, p: '', nvd_get=lambda u: '',
                              fresh_seconds=0)   # force "stale" so it tries network
    assert out['jquery'][0]['cve'] == ['CVE-2020-11022']
    assert out['jquery'][0]['cvss'] == 6.1       # enrichment came from cache


def test_clean_library_is_not_pinned_to_stale_hit(tmp_path):
    store = CVEStore(tmp_path / 'c.db')
    cve_intel.correlate(_LIBS, store=store,
                        osv_post=lambda u, p: _osv_resp('CVE-2020-11022'),
                        nvd_get=lambda u: _nvd_resp('CVE-2020-11022'))
    # Library later fixed: provider RESPONDS with an empty set (not unreachable).
    out = cve_intel.correlate(_LIBS, store=store,
                              osv_post=lambda u, p: json.dumps({'vulns': []}),
                              nvd_get=lambda u: '', fresh_seconds=0)
    assert 'jquery' not in out                    # not reported from the stale hit


def test_fresh_cache_skips_network(tmp_path):
    store = CVEStore(tmp_path / 'c.db')
    cve_intel.correlate(_LIBS, store=store,
                        osv_post=lambda u, p: _osv_resp('CVE-2020-11022'),
                        nvd_get=lambda u: _nvd_resp('CVE-2020-11022'))
    calls = []
    cve_intel.correlate(_LIBS, store=store,
                        osv_post=lambda u, p: calls.append('osv') or '',
                        nvd_get=lambda u: calls.append('nvd') or '')   # default fresh
    assert calls == []                            # within freshness → no network


def test_to_findings_carries_cvss_and_date():
    recs = [{'id': 'CVE-2020-11022', 'cve': ['CVE-2020-11022'], 'severity': 'Medium',
             'cvss': 6.1, 'published': '2020-04-29', 'summary': 'jQuery XSS'}]
    f = cve_intel.to_findings('jQuery', '1.11.0', recs)[0]
    assert f['severity'] == 'Medium' and f['source'] == 'dependency-audit'
    assert f['discriminator'] == 'CVE-2020-11022'
    assert 'CVSS 6.1' in f['detail'] and '2020-04-29' in f['detail']
    assert f['title'].startswith('Уязвимая библиотека: jQuery 1.11.0')


def test_to_findings_carries_cwe_in_detail():
    recs = [{'id': 'CVE-2020-11022', 'cve': ['CVE-2020-11022'], 'severity': 'Medium',
             'cvss': 6.1, 'cwe': ['CWE-79'], 'summary': 'jQuery XSS'}]
    f = cve_intel.to_findings('jQuery', '1.11.0', recs)[0]
    assert 'CWE-79' in f['detail']
    assert f['cwe'] == ['CWE-79']          # structured field for downstream surfaces


def test_summarize_dedups_by_cve_and_counts_severity():
    correlated = {
        'jquery': [{'cve': ['CVE-1'], 'severity': 'High'},
                   {'cve': ['CVE-2'], 'severity': 'Medium'}],
        'jquery-ui': [{'cve': ['CVE-1'], 'severity': 'High'}],   # dup CVE-1
    }
    s = cve_intel.summarize(correlated)
    assert s == {'total': 2, 'high': 1, 'medium': 1, 'info': 0}
