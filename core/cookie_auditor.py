"""cookie_auditor.py
Inspects a site's Set-Cookie headers for the security attributes that matter:
HttpOnly, Secure and SameSite. Raw header lines are read directly (urllib's
cookiejar discards SameSite), parsed, and each cookie is scored so the GUI can
flag weak configurations at a glance.
"""

import gzip
import ssl
import urllib.error
import urllib.request
import zlib
from typing import Dict, List, Optional

from utils.browser_utils import BROWSER_HEADERS


# SameSite values that actually provide CSRF protection.
_SAFE_SAMESITE = {'strict', 'lax'}


def _parse_set_cookie(line: str) -> Dict:
    """Parse one raw Set-Cookie header line into a structured record."""
    parts = [p.strip() for p in line.split(';') if p.strip()]
    if not parts:
        return {}
    name = parts[0].split('=', 1)[0].strip()

    httponly = False
    secure = False
    samesite: Optional[str] = None
    for attr in parts[1:]:
        if '=' in attr:
            key, val = attr.split('=', 1)
            key = key.strip().lower()
            if key == 'samesite':
                samesite = val.strip()
        else:
            key = attr.strip().lower()
            if key == 'httponly':
                httponly = True
            elif key == 'secure':
                secure = True

    return _score_cookie(name, httponly, secure, samesite)


def _score_cookie(name: str, httponly: bool, secure: bool,
                  samesite: Optional[str]) -> Dict:
    """Attach a 0–3 score, a verdict and human-readable issues to a cookie."""
    ss_norm = (samesite or '').strip().lower()
    ss_safe = ss_norm in _SAFE_SAMESITE

    score = sum((httponly, secure, ss_safe))
    issues: List[str] = []
    if not httponly:
        issues.append("No HttpOnly — readable from JavaScript (XSS risk)")
    if not secure:
        issues.append("No Secure — may be sent over plain HTTP")
    if not samesite:
        issues.append("No SameSite — relies on browser default (CSRF risk)")
    elif ss_norm == 'none' and not secure:
        issues.append("SameSite=None without Secure — rejected by modern browsers")

    if score == 3:
        verdict = 'Strong'
    elif score == 2:
        verdict = 'Moderate'
    else:
        verdict = 'Weak'

    return {
        'name': name,
        'httponly': httponly,
        'secure': secure,
        'samesite': samesite or '—',
        'score': score,
        'verdict': verdict,
        'issues': issues,
    }


class CookieAuditor:
    """Fetches a URL and audits the cookies it sets."""

    def __init__(self, profile: str = 'chrome_windows'):
        self._headers = BROWSER_HEADERS.get(
            profile, BROWSER_HEADERS['chrome_windows']
        ).copy()
        self._timeout = 15

    def configure(self, profile: Optional[str] = None, timeout: int = 15):
        if profile:
            self._headers = BROWSER_HEADERS.get(
                profile, BROWSER_HEADERS['chrome_windows']
            ).copy()
        self._timeout = timeout

    def audit(self, url: str) -> Dict:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {
            'url': url,
            'status': 'Error',
            'cookies': [],
            'total': 0,
            'weak': 0,
        }

        try:
            req = urllib.request.Request(url, headers=self._headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                # Raw Set-Cookie lines (cookiejar would drop SameSite).
                raw_cookies = resp.headers.get_all('Set-Cookie') or []
                result['final_url'] = resp.geturl()
                result['http_status'] = resp.status
                # Touch the body so keep-alive connections close cleanly.
                self._drain(resp)
        except urllib.error.HTTPError as e:
            # A non-2xx response can still set cookies — audit them anyway.
            raw_cookies = e.headers.get_all('Set-Cookie') or []
            result['http_status'] = e.code
        except Exception as e:
            result['error'] = str(e)
            return result

        cookies = [c for c in (_parse_set_cookie(line) for line in raw_cookies) if c]
        result['cookies'] = cookies
        result['total'] = len(cookies)
        result['weak'] = sum(1 for c in cookies if c['verdict'] == 'Weak')
        result['status'] = 'Success'
        if not cookies:
            result['note'] = 'No cookies were set on this response.'
        return result

    @staticmethod
    def _drain(resp) -> None:
        try:
            raw = resp.read()
            enc = resp.headers.get('Content-Encoding', '').lower().strip()
            if enc == 'gzip' or (not enc and raw[:2] == b'\x1f\x8b'):
                gzip.decompress(raw)
            elif enc == 'deflate':
                try:
                    zlib.decompress(raw)
                except zlib.error:
                    zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:
            pass
