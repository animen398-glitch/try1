"""Dependency vulnerability analysis (RetireJS-lite) — offline detection."""

from core import dependency_audit as da
from core.vuln_scanner import VulnScanner


# ── version parsing ─────────────────────────────────────────────────────────

def test_parse_version_and_compare():
    assert da._parse_version('3.5.10') == (3, 5, 10)
    assert da._lt('1.9.0', '3.5.0')
    assert not da._lt('3.6.0', '3.5.0')


# ── detection from script URLs ──────────────────────────────────────────────

def test_detect_jquery_from_filename():
    libs = da.detect_libraries(['https://cdn/jquery-1.8.3.min.js'])
    jq = next(lib for lib in libs if lib['library'] == 'jquery')
    assert jq['version'] == '1.8.3'
    assert jq['name'] == 'jQuery'


def test_detect_from_unpkg_at_version():
    libs = da.detect_libraries(['https://unpkg.com/lodash@4.17.10/lodash.js'])
    assert any(lib['library'] == 'lodash' and lib['version'] == '4.17.10'
               for lib in libs)


def test_detect_keeps_highest_version_on_dup():
    libs = da.detect_libraries([
        'a/jquery-1.8.3.js', 'b/jquery-3.6.0.min.js'])
    jq = next(lib for lib in libs if lib['library'] == 'jquery')
    assert jq['version'] == '3.6.0'


def test_detect_empty():
    assert da.detect_libraries([], '') == []


# ── vulnerable-range flagging ───────────────────────────────────────────────

def test_audit_flags_old_jquery():
    result = da.audit(['https://cdn/jquery-1.8.3.min.js'])
    assert result['findings']
    f = result['findings'][0]
    assert f['severity'] == 'Medium'
    assert 'jQuery' in f['title'] and '1.8.3' in f['title']
    assert f['source'] == 'dependency-audit'


def test_audit_does_not_flag_patched_version():
    result = da.audit(['https://cdn/jquery-3.6.0.min.js'])
    assert result['findings'] == []
    # The library is still detected, just not flagged.
    assert any(lib['library'] == 'jquery' for lib in result['libraries'])


def test_audit_bounded_range_only_flags_in_band():
    # Bootstrap 4.x < 4.3.1 is flagged; 4.3.1 is not; 3.4.1 (other range) clear.
    assert da.audit(['/bootstrap-4.1.0.css'])['findings']
    assert da.audit(['/bootstrap-4.3.1.css'])['findings'] == []


def test_audit_high_severity_lodash():
    result = da.audit(['/lodash-4.17.10.js'])
    assert result['findings'][0]['severity'] == 'High'


def test_audit_annotates_library_vulnerabilities():
    result = da.audit(['/handlebars-4.0.0.js'])
    lib = next(lib for lib in result['libraries']
               if lib['library'] == 'handlebars')
    assert lib['vulnerabilities']
    assert lib['vulnerabilities'][0]['severity'] == 'High'


# ── vuln-scanner integration (findings feed the risk score) ─────────────────

def test_vuln_scanner_merges_dependency_findings():
    recon = {'url': 'https://ex.com',
             'dependencies': da.audit(['/jquery-1.8.3.min.js'])}
    findings = VulnScanner().scan(recon, {})
    assert any(f.get('source') == 'dependency-audit' for f in findings)
    summary = VulnScanner.summarize(findings)
    assert summary['medium'] >= 1


def test_vuln_scanner_tolerates_no_dependencies():
    findings = VulnScanner().scan({'url': 'https://ex.com'}, {})
    assert isinstance(findings, list)   # no crash without the key


# ── render (offline) ────────────────────────────────────────────────────────

def test_render_html_flags_vulnerable_and_clean():
    out = da.render_html(da.audit(['/jquery-1.8.3.min.js', '/vue-3.4.0.js']))
    assert '<script' not in out.lower()
    assert 'jQuery 1.8.3' in out
    assert 'Vue.js 3.4.0' in out
    assert 'нет известных' in out          # vue is clean


def test_render_html_empty_placeholder():
    assert 'не обнаружены' in da.render_html({'libraries': []})
    assert 'не обнаружены' in da.render_html(None)
