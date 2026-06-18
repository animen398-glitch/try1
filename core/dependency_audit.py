"""core/dependency_audit.py
Offline dependency-vulnerability analysis (RetireJS-lite), stdlib only.

Detects front-end JavaScript libraries and their versions from ``<script src>``
URLs (and a few inline markers), then flags versions that fall in a known
*vulnerable* range using a small, bundled signature table. Pure and
deterministic (architectural invariants I1/I5): one ``audit(scripts, html)``
call returns library detections plus findings shaped exactly like the vuln
scanner's, so they fold straight into the existing risk score / report. No
network and no dependency — the opposite of pulling the full RetireJS DB.

The signature table is intentionally small and high-confidence (a handful of
widely-deployed libraries with well-known CVEs) rather than exhaustive; it is
trivial to extend as a single data structure.
"""

import html as _html
import re
from typing import Dict, List, Optional, Tuple

# library -> regexes that capture the version as group(1) from a script URL or
# inline reference. Names are matched case-insensitively.
_LIB_PATTERNS: Dict[str, List[str]] = {
    'jquery': [r'jquery[-./]?(\d+\.\d+(?:\.\d+)?)', r'/jquery@(\d+\.\d+(?:\.\d+)?)'],
    'angular': [r'angular(?:\.min)?[-./](\d+\.\d+(?:\.\d+)?)',
                r'/angular(?:js)?@(\d+\.\d+(?:\.\d+)?)'],
    'react': [r'react[-@/](\d+\.\d+(?:\.\d+)?)'],
    'vue': [r'vue[-@/](\d+\.\d+(?:\.\d+)?)'],
    'lodash': [r'lodash[-@./](\d+\.\d+(?:\.\d+)?)'],
    'bootstrap': [r'bootstrap[-@./](\d+\.\d+(?:\.\d+)?)'],
    'moment': [r'moment[-@./](\d+\.\d+(?:\.\d+)?)'],
    'jquery-ui': [r'jquery[-.]ui[-@./](\d+\.\d+(?:\.\d+)?)'],
    'handlebars': [r'handlebars[-@./](\d+\.\d+(?:\.\d+)?)'],
    'dompurify': [r'(?:dom)?purify[-@./](\d+\.\d+(?:\.\d+)?)'],
    'axios': [r'axios[-@./](\d+\.\d+(?:\.\d+)?)'],
    'underscore': [r'underscore[-@./](\d+\.\d+(?:\.\d+)?)'],
    # Leading delimiter so 'bookmarked'/'remarked' don't false-positive.
    'marked': [r'(?:^|[/@._-])marked[-@./](\d+\.\d+(?:\.\d+)?)'],
}

# library -> list of vulnerable ranges. ``below`` means "any version < below"
# (the usual "fixed in X" form); ``at_or_above`` optionally bounds the range
# from below so an old-but-patched branch is not flagged.
_VULN_DB: Dict[str, List[Dict]] = {
    'jquery': [
        {'below': '3.5.0', 'severity': 'Medium',
         'detail': 'jQuery < 3.5.0: XSS via htmlPrefilter / jQuery.htmlPrefilter (CVE-2020-11022/11023).'},
        {'below': '1.9.0', 'severity': 'Medium',
         'detail': 'jQuery < 1.9.0: selector-based XSS (CVE-2012-6708).'},
    ],
    'jquery-ui': [
        {'below': '1.12.0', 'severity': 'Medium',
         'detail': 'jQuery UI < 1.12.0: XSS in dialog/tooltip (CVE-2016-7103 / 2021-41182…).'},
    ],
    'angular': [
        {'below': '1.8.0', 'severity': 'Medium',
         'detail': 'AngularJS < 1.8.0: multiple sandbox-bypass / XSS issues (EOL — unsupported).'},
    ],
    'bootstrap': [
        {'below': '3.4.1', 'severity': 'Medium',
         'detail': 'Bootstrap < 3.4.1: XSS in data-target / tooltip (CVE-2019-8331…).'},
        {'at_or_above': '4.0.0', 'below': '4.3.1', 'severity': 'Medium',
         'detail': 'Bootstrap 4.x < 4.3.1: XSS in tooltip/popover (CVE-2019-8331).'},
    ],
    'lodash': [
        {'below': '4.17.21', 'severity': 'High',
         'detail': 'lodash < 4.17.21: prototype pollution / command injection (CVE-2021-23337, 2020-8203).'},
    ],
    'moment': [
        {'below': '2.29.4', 'severity': 'Medium',
         'detail': 'moment < 2.29.4: ReDoS / path traversal (CVE-2022-31129, 2022-24785).'},
    ],
    'handlebars': [
        {'below': '4.7.7', 'severity': 'High',
         'detail': 'handlebars < 4.7.7: prototype pollution / RCE in templates (CVE-2021-23369…).'},
    ],
    'dompurify': [
        {'below': '2.4.0', 'severity': 'High',
         'detail': 'DOMPurify < 2.4.0: mutation-XSS sanitiser bypass.'},
    ],
    'axios': [
        {'below': '1.6.0', 'severity': 'High',
         'detail': 'axios < 1.6.0: SSRF / credential leak on cross-host redirect (CVE-2023-45857).'},
        {'below': '0.21.2', 'severity': 'High',
         'detail': 'axios < 0.21.2: SSRF & ReDoS in URL/proxy handling (CVE-2021-3749, 2020-28168).'},
    ],
    'underscore': [
        {'below': '1.12.1', 'severity': 'High',
         'detail': 'underscore < 1.12.1: arbitrary code execution via _.template (CVE-2021-23358).'},
    ],
    'marked': [
        {'below': '4.0.10', 'severity': 'Medium',
         'detail': 'marked < 4.0.10: ReDoS in block/inline tokenizer (CVE-2022-21680/21681).'},
    ],
}

_DISPLAY_NAME = {
    'jquery': 'jQuery', 'jquery-ui': 'jQuery UI', 'angular': 'AngularJS',
    'react': 'React', 'vue': 'Vue.js', 'lodash': 'lodash',
    'bootstrap': 'Bootstrap', 'moment': 'moment', 'handlebars': 'handlebars',
    'dompurify': 'DOMPurify', 'axios': 'axios', 'underscore': 'Underscore.js',
    'marked': 'marked',
}


def _parse_version(v: str) -> Tuple[int, ...]:
    """``"3.5.10"`` → ``(3, 5, 10)``; non-numeric parts are dropped."""
    parts = []
    for chunk in v.split('.'):
        m = re.match(r'\d+', chunk)
        parts.append(int(m.group(0)) if m else 0)
    return tuple(parts) or (0,)


def _lt(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _ge(a: str, b: str) -> bool:
    return _parse_version(a) >= _parse_version(b)


def detect_libraries(scripts: Optional[List[str]] = None,
                     html: str = '') -> List[Dict]:
    """Detect ``{library, name, version}`` from script URLs and the page body.

    De-duplicated by (library, version); the highest version wins when a library
    appears more than once with different versions (a page may load several).
    """
    # Robust to a heterogeneous corpus: skip any non-string element rather than
    # letting ``str.join`` raise on a None/dict the caller slipped in.
    corpus = [s for s in (scripts or []) if isinstance(s, str)]
    if isinstance(html, str) and html:
        corpus.append(html)
    blob = '\n'.join(corpus)

    best: Dict[str, str] = {}
    for lib, patterns in _LIB_PATTERNS.items():
        for pat in patterns:
            for m in re.finditer(pat, blob, re.IGNORECASE):
                ver = m.group(1)
                if lib not in best or _lt(best[lib], ver):
                    best[lib] = ver
    return [
        {'library': lib, 'name': _DISPLAY_NAME.get(lib, lib), 'version': ver}
        for lib, ver in sorted(best.items())
    ]


def _vulns_for(lib: str, version: str) -> List[Dict]:
    out = []
    for rng in _VULN_DB.get(lib, []):
        below = rng.get('below')
        floor = rng.get('at_or_above')
        if below and not _lt(version, below):
            continue
        if floor and not _ge(version, floor):
            continue
        out.append({'severity': rng['severity'], 'detail': rng['detail'],
                    'fixed_in': below})
    return out


def audit(scripts: Optional[List[str]] = None, html: str = '') -> Dict:
    """Detect libraries and flag known-vulnerable versions.

    Returns ``{'libraries': [...], 'findings': [...]}``. Each library carries its
    matched ``vulnerabilities`` (for display); each finding is
    ``{severity, title, detail, source='dependency-audit'}`` — the vuln-scanner
    shape, so callers can merge it directly into the findings list.
    """
    libraries = detect_libraries(scripts, html)
    findings: List[Dict] = []
    for lib in libraries:
        vulns = _vulns_for(lib['library'], lib['version'])
        lib['vulnerabilities'] = vulns
        for v in vulns:
            findings.append({
                'severity': v['severity'],
                'title': f"Уязвимая библиотека: {lib['name']} {lib['version']}",
                'detail': v['detail'],
                'source': 'dependency-audit',
            })
    return {'libraries': libraries, 'findings': findings}


_SEV_COLOR = {'High': '#c62828', 'Medium': '#f9a825', 'Info': '#2e7d32'}
# Severity rank for "pick the worst" — keyed lookup with a safe default so an
# out-of-vocabulary severity (e.g. a hand-built result) sorts last instead of
# raising (the old ``tuple.index`` did).
_SEV_RANK = {'High': 0, 'Medium': 1, 'Info': 2}


def render_html(result: Optional[Dict]) -> str:
    """Render detected libraries (vulnerable ones highlighted) as an offline
    inline-CSS fragment. ``result`` is the dict ``audit`` returns."""
    e = _html.escape
    libraries = (result or {}).get('libraries') or []
    if not libraries:
        return ('<p style="font-size:13px;color:#999;">'
                'JS-библиотеки с версиями не обнаружены.</p>')
    rows = []
    for lib in libraries:
        vulns = lib.get('vulnerabilities') or []
        if vulns:
            worst = min(vulns, key=lambda v: _SEV_RANK.get(v.get('severity'), 99))
            color = _SEV_COLOR.get(worst.get('severity'), '#555')
            # CVE Intelligence meta (CVE id · CVSS · published date) when the CVE
            # engine enriched this entry; absent for bundled-table vulns (back-compat).
            meta_bits = []
            if worst.get('cve'):
                meta_bits.append(e(str(worst['cve'])))
            if worst.get('cvss') is not None:
                meta_bits.append(f'CVSS {e(str(worst["cvss"]))}')
            if worst.get('published'):
                meta_bits.append(e(str(worst['published'])))
            meta = (f'<span style="color:#888;font-size:11px;"> '
                    f'[{" · ".join(meta_bits)}]</span>') if meta_bits else ''
            detail = (f'{meta}<br><span style="color:{color};font-size:11px;">'
                      f'{e(worst["detail"])}</span>')
        else:
            color = '#2e7d32'
            detail = ('<span style="color:#2e7d32;font-size:11px;"> — нет известных '
                      'уязвимостей</span>')
        rows.append(
            f'<li style="margin:3px 0;font-size:12px;">'
            f'<b style="color:{color};">{e(lib["name"])} {e(lib["version"])}</b>'
            f'{detail}</li>'
        )
    return (f'<ul style="margin:6px 0;padding-left:18px;">{"".join(rows)}</ul>')
