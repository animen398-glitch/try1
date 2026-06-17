"""
VulnScanner — static analysis of recon + dynamic (+ optional cookie) results.
Produces findings with severity: High / Medium / Info.
"""
import re
from typing import Dict, List, Optional

# HSTS shorter than ~6 months is considered weak.
_HSTS_MIN_MAX_AGE = 15768000

SEVERITY_HIGH   = 'High'
SEVERITY_MEDIUM = 'Medium'
SEVERITY_INFO   = 'Info'

# Weights used by summarize() to turn a finding list into a single risk score.
_SEVERITY_WEIGHTS = {SEVERITY_HIGH: 5, SEVERITY_MEDIUM: 2, SEVERITY_INFO: 1}

_EXPECTED_SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
]

_SENSITIVE_PATH_PATTERNS = [
    '.env', '.git/', '/admin', '/debug', 'wp-login',
    '/phpmyadmin', '/actuator/', '/swagger', '/graphql',
    '/api-docs', '/config.', '/credentials', '/passwd',
    '?id=', '?user=', '?file=',
]


class VulnScanner:
    """Analyses recon + dynamic results and returns a list of finding dicts."""

    def scan(self, recon_result: Dict, dynamic_result: Dict,
             cookie_result: Optional[Dict] = None) -> List[Dict]:
        findings: List[Dict] = []
        self._check_https(recon_result, findings)
        self._check_secrets(dynamic_result, findings)
        self._check_auth_headers(dynamic_result, findings)
        self._check_security_headers(recon_result, findings)
        self._check_csp_weakness(recon_result, findings)
        self._check_hsts_weakness(recon_result, findings)
        self._check_referrer_policy(recon_result, findings)
        self._check_frame_options(recon_result, findings)
        self._check_server_disclosure(recon_result, findings)
        self._check_dependencies(recon_result, findings)
        self._check_sensitive_paths(dynamic_result, findings)
        self._check_cookies(cookie_result, findings)
        self._check_cms_info(recon_result, findings)
        self._check_pwa(recon_result, findings)
        self._check_runtime_globals(dynamic_result, findings)
        return findings

    @staticmethod
    def summarize(findings: List[Dict]) -> Dict:
        """Aggregate findings into severity counts plus a weighted risk score.

        Risk score = sum of per-finding severity weights (High=5, Medium=2,
        Info=1); 0 means no findings. Handy for report headers and sorting.
        """
        counts = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_INFO: 0}
        for f in findings:
            sev = f.get('severity')
            if sev in counts:
                counts[sev] += 1
        score = sum(_SEVERITY_WEIGHTS[s] * n for s, n in counts.items())
        return {
            'high': counts[SEVERITY_HIGH],
            'medium': counts[SEVERITY_MEDIUM],
            'info': counts[SEVERITY_INFO],
            'total': sum(counts.values()),
            'risk_score': score,
        }

    # ---------------------------------------------------------------- High

    def _check_https(self, recon: Dict, findings: List[Dict]):
        if recon.get('url', '').startswith('http://'):
            findings.append({
                'severity': SEVERITY_HIGH,
                'title': 'Site served over plain HTTP (not HTTPS)',
                'detail': 'All traffic is unencrypted and vulnerable to interception.',
            })

    def _check_secrets(self, dynamic: Dict, findings: List[Dict]):
        for s in dynamic.get('secrets_found', []):
            findings.append({
                'severity': SEVERITY_HIGH,
                'title': f"Secret exposed in API response [{s['type']}]",
                'detail': (
                    f"key='{s['key']}'  =>  '{s['preview']}'"
                    f"  |  {s.get('source_url', '')[-70:]}"
                ),
            })

    def _check_auth_headers(self, dynamic: Dict, findings: List[Dict]):
        auth = dynamic.get('auth_headers', [])
        if auth:
            header_names = ', '.join(sorted({a['header'] for a in auth}))
            findings.append({
                'severity': SEVERITY_HIGH,
                'title': f"Auth/session tokens in {len(auth)} intercepted request(s)",
                'detail': f"Headers: {header_names}",
            })

    # ---------------------------------------------------------------- Medium

    def _check_security_headers(self, recon: Dict, findings: List[Dict]):
        present = {k.lower() for k in recon.get('security_headers', {})}
        missing = [h for h in _EXPECTED_SECURITY_HEADERS if h not in present]
        if missing:
            findings.append({
                'severity': SEVERITY_MEDIUM,
                'title': f"Missing security headers ({len(missing)})",
                'detail': ', '.join(missing),
            })

    def _check_csp_weakness(self, recon: Dict, findings: List[Dict]):
        csp = recon.get('security_headers', {}).get('content-security-policy', '')
        if not csp:
            return  # absence is covered by _check_security_headers
        low = csp.lower()
        weak = [t for t in ('unsafe-inline', 'unsafe-eval') if t in low]
        if '*' in re.split(r'[;\s]+', low):   # a bare wildcard source
            weak.append('wildcard source (*)')
        if weak:
            findings.append({
                'severity': SEVERITY_MEDIUM,
                'title': 'Weak Content-Security-Policy',
                'detail': ', '.join(weak),
            })

    def _check_hsts_weakness(self, recon: Dict, findings: List[Dict]):
        hsts = recon.get('security_headers', {}).get('strict-transport-security', '')
        if not hsts:
            return  # absence is covered by _check_security_headers
        low = hsts.lower()
        m = re.search(r'max-age\s*=\s*(\d+)', low)
        max_age = int(m.group(1)) if m else 0
        if max_age < _HSTS_MIN_MAX_AGE:
            findings.append({
                'severity': SEVERITY_MEDIUM,
                'title': 'HSTS max-age too short',
                'detail': f'max-age={max_age} (< {_HSTS_MIN_MAX_AGE} ≈ 6 months)',
            })
        elif 'includesubdomains' not in low:
            findings.append({
                'severity': SEVERITY_INFO,
                'title': 'HSTS without includeSubDomains',
                'detail': hsts[:120],
            })

    def _check_referrer_policy(self, recon: Dict, findings: List[Dict]):
        rp = recon.get('security_headers', {}).get('referrer-policy', '').strip().lower()
        if rp and rp in ('unsafe-url', 'no-referrer-when-downgrade'):
            findings.append({
                'severity': SEVERITY_INFO,
                'title': 'Weak Referrer-Policy',
                'detail': f'{rp} — may leak full URLs to third parties.',
            })

    def _check_frame_options(self, recon: Dict, findings: List[Dict]):
        xfo = recon.get('security_headers', {}).get('x-frame-options', '').strip().upper()
        # Absence is covered by _check_security_headers; flag weak/legacy values.
        if xfo and xfo not in ('DENY', 'SAMEORIGIN'):
            findings.append({
                'severity': SEVERITY_MEDIUM,
                'title': 'Weak X-Frame-Options (clickjacking risk)',
                'detail': f'{xfo} — only DENY/SAMEORIGIN reliably prevent framing.',
            })

    def _check_server_disclosure(self, recon: Dict, findings: List[Dict]):
        for k, v in recon.get('server_headers', {}).items():
            if k.lower() in ('server', 'x-powered-by', 'x-generator') and v:
                findings.append({
                    'severity': SEVERITY_MEDIUM,
                    'title': f"Server technology disclosed via {k} header",
                    'detail': v[:120],
                })

    def _check_dependencies(self, recon: Dict, findings: List[Dict]):
        """Merge known-vulnerable JS library findings from recon's dependency
        audit (already in finding shape: severity/title/detail/source)."""
        dep = recon.get('dependencies')
        if isinstance(dep, dict):
            findings.extend(dep.get('findings', []))

    def _check_cookies(self, cookie_result: Optional[Dict], findings: List[Dict]):
        """Flag insecure cookies from a CookieAuditor result (if provided).

        Tagged ``category='cookie'`` (the canonical finding_fingerprint category
        the adapter already infers from the title — explicit here so consumers
        like the attack-surface graph can tell a cookie finding apart without
        title sniffing, e.g. to avoid double-counting it against the dedicated
        'Weak Cookies' surface category)."""
        if not cookie_result or cookie_result.get('status') != 'Success':
            return
        for c in cookie_result.get('cookies', []):
            ss = str(c.get('samesite', '')).strip().lower()
            # SameSite=None without Secure is the clearest cookie-level risk.
            if ss == 'none' and not c.get('secure'):
                findings.append({
                    'severity': SEVERITY_HIGH,
                    'title': f"Cookie '{c.get('name', '')}' SameSite=None without Secure",
                    'detail': 'Rejected by modern browsers and exposed cross-site.',
                    'category': 'cookie',
                })
            elif c.get('verdict') == 'Weak':
                findings.append({
                    'severity': SEVERITY_MEDIUM,
                    'title': f"Weakly protected cookie: {c.get('name', '')}",
                    'detail': '; '.join(c.get('issues', [])) or 'missing security flags',
                    'category': 'cookie',
                })

    def _check_sensitive_paths(self, dynamic: Dict, findings: List[Dict]):
        seen: set = set()
        for ep in dynamic.get('endpoints', []):
            needle = (ep.get('path', '') + ep.get('url', '')).lower()
            for pat in _SENSITIVE_PATH_PATTERNS:
                if pat in needle and pat not in seen:
                    seen.add(pat)
                    findings.append({
                        'severity': SEVERITY_MEDIUM,
                        'title': f"Sensitive path pattern detected: {pat}",
                        'detail': ep.get('url', '')[-100:],
                    })
                    break

    # ---------------------------------------------------------------- Info

    def _check_cms_info(self, recon: Dict, findings: List[Dict]):
        cms = recon.get('cms', [])
        if cms:
            findings.append({
                'severity': SEVERITY_INFO,
                'title': f"CMS/Stack fingerprinted: {', '.join(cms)}",
                'detail': 'Technology disclosure may aid targeted attacks.',
            })

    def _check_pwa(self, recon: Dict, findings: List[Dict]):
        if recon.get('pwa_manifest'):
            url = recon['pwa_manifest'].get('url', '')
            findings.append({
                'severity': SEVERITY_INFO,
                'title': 'PWA manifest found — app-level metadata exposed',
                'detail': url,
            })

    def _check_runtime_globals(self, dynamic: Dict, findings: List[Dict]):
        rg = dynamic.get('runtime_globals', {})
        if rg:
            findings.append({
                'severity': SEVERITY_INFO,
                'title': f"JS framework globals detected: {', '.join(rg.keys())}",
                'detail': 'Confirmed via window.* probe in headless browser.',
            })
