"""
VulnScanner — static analysis of recon + dynamic results.
Produces findings with severity: High / Medium / Info.
"""
from typing import Dict, List

SEVERITY_HIGH   = 'High'
SEVERITY_MEDIUM = 'Medium'
SEVERITY_INFO   = 'Info'

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

    def scan(self, recon_result: Dict, dynamic_result: Dict) -> List[Dict]:
        findings: List[Dict] = []
        self._check_https(recon_result, findings)
        self._check_secrets(dynamic_result, findings)
        self._check_auth_headers(dynamic_result, findings)
        self._check_security_headers(recon_result, findings)
        self._check_server_disclosure(recon_result, findings)
        self._check_sensitive_paths(dynamic_result, findings)
        self._check_cms_info(recon_result, findings)
        self._check_pwa(recon_result, findings)
        self._check_runtime_globals(dynamic_result, findings)
        return findings

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

    def _check_server_disclosure(self, recon: Dict, findings: List[Dict]):
        for k, v in recon.get('server_headers', {}).items():
            if k.lower() in ('server', 'x-powered-by', 'x-generator') and v:
                findings.append({
                    'severity': SEVERITY_MEDIUM,
                    'title': f"Server technology disclosed via {k} header",
                    'detail': v[:120],
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
