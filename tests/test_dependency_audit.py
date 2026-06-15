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


# ── extended signatures (D2): axios / underscore / marked ────────────────────

def test_audit_flags_vulnerable_axios():
    result = da.audit(['https://unpkg.com/axios@0.21.1/dist/axios.min.js'])
    f = result['findings'][0]
    assert f['severity'] == 'High'
    assert 'axios' in f['title'] and '0.21.1' in f['title']


def test_audit_does_not_flag_patched_axios():
    assert da.audit(['/axios-1.6.2.min.js'])['findings'] == []
    assert any(lib['library'] == 'axios'
               for lib in da.audit(['/axios-1.6.2.min.js'])['libraries'])


def test_audit_flags_underscore_template_rce():
    result = da.audit(['/underscore-1.12.0.js'])
    f = result['findings'][0]
    assert f['severity'] == 'High'
    assert 'Underscore.js' in f['title']


def test_audit_flags_marked_redos():
    result = da.audit(['https://cdn/marked@4.0.0/marked.min.js'])
    f = result['findings'][0]
    assert f['severity'] == 'Medium'
    assert 'marked' in f['title'] and '4.0.0' in f['title']


def test_audit_marked_patched_is_clean():
    assert da.audit(['/marked-4.0.10.min.js'])['findings'] == []


def test_audit_marked_not_confused_by_bookmarked():
    # 'bookmarked-2.0.js' must NOT be detected as the 'marked' library.
    libs = da.detect_libraries(['/bookmarked-2.0.js'])
    assert all(lib['library'] != 'marked' for lib in libs)


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


# ── robustness: malformed input degrades, never raises ───────────────────────

def test_detect_libraries_skips_non_string_corpus():
    # A heterogeneous scripts list (None / dict / bytes) must not raise.
    scripts = ['https://cdn/jquery-1.8.3.min.js', None, {'x': 1}, 123]
    libs = da.detect_libraries(scripts=scripts)
    assert any(lib['library'] == 'jquery' and lib['version'] == '1.8.3'
               for lib in libs)


def test_audit_tolerates_non_string_html():
    # Non-string html (e.g. bytes) is ignored rather than crashing str.join.
    res = da.audit(scripts=['/lodash-4.17.20.js'], html=b'<bytes>')
    assert any(f['severity'] == 'High' for f in res['findings'])  # lodash < 4.17.21


def test_render_html_tolerates_unknown_severity():
    # A hand-built result with an out-of-vocabulary severity must not raise.
    result = {'libraries': [{'name': 'X', 'version': '1.0',
                             'vulnerabilities': [{'severity': 'Critical',
                                                  'detail': 'boom'}]}]}
    out = da.render_html(result)
    assert 'boom' in out and 'X 1.0' in out
