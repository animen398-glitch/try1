"""Tests for core/osv_correlation.py — OSV.dev CVE correlation (offline, stubbed).

The single network seam (``_post_json``) is injected/monkeypatched so parsing,
caching, severity mapping, finding shaping and the collection-runner phase are all
exercised without touching the network.
"""

import json

import pytest

from core import osv_correlation as osv


@pytest.fixture(autouse=True)
def _clear_cache():
    osv.clear_cache()
    yield
    osv.clear_cache()


def _resp(vulns):
    return json.dumps({'vulns': vulns})


# ── pure parser + severity ───────────────────────────────────────────────────

def test_parse_osv_extracts_cve_and_severity():
    text = _resp([
        {'id': 'GHSA-aaaa', 'aliases': ['CVE-2020-11022', 'GHSA-aaaa'],
         'summary': 'XSS', 'database_specific': {'severity': 'MODERATE'}},
        {'id': 'GHSA-bbbb', 'aliases': ['CVE-2021-23337'],
         'summary': 'RCE', 'database_specific': {'severity': 'CRITICAL'}},
    ])
    out = osv._parse_osv(text)
    assert len(out) == 2
    assert out[0]['cve'] == ['CVE-2020-11022']      # GHSA alias filtered out
    assert out[0]['severity'] == 'Medium'           # MODERATE -> Medium
    assert out[1]['severity'] == 'High'             # CRITICAL collapses to High


def test_severity_falls_back_to_numeric_cvss_then_default():
    # No database_specific.severity: numeric CVSS score is used.
    by_score = osv._parse_osv(_resp([
        {'id': 'X', 'severity': [{'type': 'CVSS_V3', 'score': '8.1'}]}]))
    assert by_score[0]['severity'] == 'High'
    # A CVSS *vector* string is not re-scored -> default Medium.
    by_vector = osv._parse_osv(_resp([
        {'id': 'Y', 'severity': [{'type': 'CVSS_V3',
                                  'score': 'CVSS:3.1/AV:N/AC:L/PR:N'}]}]))
    assert by_vector[0]['severity'] == 'Medium'


def test_parse_osv_degrades_on_malformed_or_empty():
    assert osv._parse_osv('') == []
    assert osv._parse_osv('not json') == []
    assert osv._parse_osv('{"no_vulns": true}') == []
    assert osv._parse_osv(_resp([])) == []


def test_ecosystem_package_defaults_to_npm():
    assert osv._ecosystem_package('lodash') == ('npm', 'lodash')
    assert osv._ecosystem_package('angular') == ('npm', 'angular')


# ── correlate + cache ────────────────────────────────────────────────────────

def test_correlate_returns_only_libraries_with_vulns():
    def fake_post(url, payload, **kw):
        name = payload['package']['name']
        if name == 'jquery':
            return _resp([{'id': 'GHSA-1', 'aliases': ['CVE-1'],
                           'database_specific': {'severity': 'HIGH'}}])
        return _resp([])     # react: clean

    libs = [{'library': 'jquery', 'name': 'jQuery', 'version': '3.4.1'},
            {'library': 'react', 'name': 'React', 'version': '18.0.0'}]
    out = osv.correlate(libs, post=fake_post)
    assert set(out) == {'jquery'}                    # clean react omitted
    assert out['jquery'][0]['cve'] == ['CVE-1']


def test_correlate_caches_per_package_version():
    calls = []

    def fake_post(url, payload, **kw):
        calls.append(payload['package']['name'])
        return _resp([{'id': 'GHSA-1', 'aliases': ['CVE-1'],
                       'database_specific': {'severity': 'HIGH'}}])

    libs = [{'library': 'jquery', 'name': 'jQuery', 'version': '3.4.1'}]
    osv.correlate(libs, post=fake_post)
    osv.correlate(libs, post=fake_post)              # same key -> cache hit
    assert calls == ['jquery']                       # queried once
    assert osv.clear_cache() >= 1


def test_correlate_skips_libs_without_version():
    out = osv.correlate([{'library': 'jquery', 'name': 'jQuery'}],
                        post=lambda *a, **k: _resp([{'id': 'X'}]))
    assert out == {}


# ── finding shape ────────────────────────────────────────────────────────────

def test_to_findings_shape_and_discriminator():
    vulns = [{'id': 'GHSA-1', 'cve': ['CVE-2020-11022'], 'severity': 'Medium',
              'summary': 'XSS in htmlPrefilter'}]
    findings = osv.to_findings('jQuery', '3.4.1', vulns)
    f = findings[0]
    assert f['source'] == 'dependency-audit'         # folds like bundled audit
    assert f['discriminator'] == 'CVE-2020-11022'    # distinct CVEs stay distinct
    assert 'CVE-2020-11022' in f['title']
    assert f['title'].startswith('Уязвимая библиотека: jQuery 3.4.1')
    assert f['severity'] == 'Medium'


# ── collection-runner phase: supersede + fold ────────────────────────────────

def _report_with_jquery():
    bundled = {'severity': 'Medium',
               'title': 'Уязвимая библиотека: jQuery 3.4.1',
               'detail': 'bundled', 'source': 'dependency-audit'}
    other = {'severity': 'High', 'title': 'Plain HTTP', 'detail': '',
             'source': 'vuln'}
    return {'phases': {
        'recon': {'status': 'Success', 'data': {'dependencies': {
            'libraries': [{'library': 'jquery', 'name': 'jQuery',
                           'version': '3.4.1', 'vulnerabilities': [{}]}],
            'findings': [bundled]}}},
        'vulns': {'status': 'Success',
                  'findings': [dict(bundled), dict(other)]},
    }}


def test_phase_osv_supersedes_bundled_and_folds(tmp_path, monkeypatch):
    from core.collection_runner import CollectionRunner

    monkeypatch.setattr(osv, '_post_json', lambda url, payload, **kw: _resp([
        {'id': 'GHSA-1', 'aliases': ['CVE-2020-11022'],
         'database_specific': {'severity': 'MODERATE'}, 'summary': 'XSS'},
        {'id': 'GHSA-2', 'aliases': ['CVE-2020-11023'],
         'database_specific': {'severity': 'MODERATE'}, 'summary': 'XSS2'},
    ]))
    # Keep the NVD enrichment offline/deterministic (degrade → OSV-only records).
    from core import nvd_provider
    monkeypatch.setattr(nvd_provider, '_get_text', lambda url, **kw: '')

    runner = CollectionRunner(osv=True)
    report = _report_with_jquery()
    out = runner._phase_osv(report, tmp_path)

    assert out['status'] == 'Success'
    assert (tmp_path / 'recon' / 'osv.json').exists()

    vuln_findings = report['phases']['vulns']['findings']
    titles = [f['title'] for f in vuln_findings]
    # Bundled jQuery finding superseded (exact-prefix, no CVE) is gone…
    assert 'Уязвимая библиотека: jQuery 3.4.1' not in titles
    # …replaced by the two OSV CVE findings, and the unrelated one kept.
    assert sum('CVE-2020-1102' in t for t in titles) == 2
    assert 'Plain HTTP' in titles
    # Summary recomputed over the new set.
    assert report['phases']['vulns']['summary']['total'] == 3
    # Library display vulns enriched from the CVE engine (CVE id + summary).
    lib = report['phases']['recon']['data']['dependencies']['libraries'][0]
    assert len(lib['vulnerabilities']) == 2
    assert 'GHSA-1' in lib['vulnerabilities'][0]['detail']
    assert lib['vulnerabilities'][0]['cve'] == 'CVE-2020-11022'   # CVE surfaced
    # CVE summary stamped for the risk metric (two unique CVEs).
    assert out['data']['cve_summary']['total'] == 2


def test_phase_osv_no_libraries_is_clean(tmp_path):
    from core.collection_runner import CollectionRunner
    runner = CollectionRunner(osv=True)
    report = {'phases': {'recon': {'status': 'Success',
                                   'data': {'dependencies': {'libraries': []}}}}}
    out = runner._phase_osv(report, tmp_path)
    assert out['status'] == 'No libraries'


def test_phase_osv_no_advisories_keeps_bundled(tmp_path, monkeypatch):
    from core.collection_runner import CollectionRunner
    monkeypatch.setattr(osv, '_post_json', lambda *a, **k: _resp([]))
    runner = CollectionRunner(osv=True)
    report = _report_with_jquery()
    out = runner._phase_osv(report, tmp_path)
    assert out['status'] == 'Success'
    # OSV found nothing -> bundled finding untouched (fallback intact).
    titles = [f['title'] for f in report['phases']['vulns']['findings']]
    assert 'Уязвимая библиотека: jQuery 3.4.1' in titles
