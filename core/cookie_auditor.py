"""cookie_auditor.py
Inspects a site's Set-Cookie headers for the security attributes that matter:
HttpOnly, Secure and SameSite. Raw header lines are read directly (urllib's
cookiejar discards SameSite), parsed, and each cookie is scored so the GUI can
flag weak configurations at a glance.
"""

import gzip
from pathlib import Path
import ssl
import urllib.error
import urllib.request
import zlib
from typing import Dict, List, Optional

from utils.browser_utils import BROWSER_HEADERS


# SameSite values that actually provide CSRF protection.
_SAFE_SAMESITE = {'strict', 'lax'}


class CookieFileError(ValueError):
    """Raised when a cookies.txt file is missing or not Netscape-formatted."""


def mask_cookie_value(value: str) -> str:
    """Mask a cookie value while keeping enough context for UX diagnostics."""
    value = str(value or '')
    if not value:
        return ''
    return f'{value[:4]}...len={len(value)}'


def _parse_netscape_cookie_line(line: str, line_no: int) -> Dict:
    parts = line.rstrip('\n').split('\t')
    if len(parts) != 7:
        raise CookieFileError(
            f'cookies.txt line {line_no}: expected Netscape format with '
            '7 tab-separated columns'
        )
    domain, include_subdomains, path, secure, expires, name, value = parts
    if not domain or not path or not name:
        raise CookieFileError(
            f'cookies.txt line {line_no}: domain, path and cookie name are required'
        )
    flag = include_subdomains.upper()
    secure_flag = secure.upper()
    if flag not in {'TRUE', 'FALSE'} or secure_flag not in {'TRUE', 'FALSE'}:
        raise CookieFileError(
            f'cookies.txt line {line_no}: include-subdomains and secure '
            'columns must be TRUE or FALSE'
        )
    if expires and not expires.isdigit():
        raise CookieFileError(
            f'cookies.txt line {line_no}: expiration must be a Unix timestamp or 0'
        )
    return {
        'domain': domain,
        'include_subdomains': flag == 'TRUE',
        'path': path,
        'secure': secure_flag == 'TRUE',
        'expires': expires,
        'name': name,
        'value_masked': mask_cookie_value(value),
    }


def read_cookies_txt(path: str) -> List[Dict]:
    """Read a Netscape cookies.txt file and return only masked cookie values."""
    cookie_path = Path(path).expanduser()
    if not cookie_path.exists():
        raise CookieFileError(f'cookies.txt not found: {cookie_path}')
    if not cookie_path.is_file():
        raise CookieFileError(f'cookies.txt is not a file: {cookie_path}')

    cookies: List[Dict] = []
    try:
        lines = cookie_path.read_text(encoding='utf-8').splitlines()
    except UnicodeDecodeError as exc:
        raise CookieFileError('cookies.txt must be UTF-8 text') from exc

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        cookies.append(_parse_netscape_cookie_line(line, line_no))
    if not cookies:
        raise CookieFileError('cookies.txt does not contain any cookie rows')
    return cookies


def validate_cookies_txt(path: Optional[str]) -> Dict:
    """Validate cookies.txt for GUI preflight without exposing raw values."""
    if not path:
        return {'status': 'Skipped', 'cookies': [], 'total': 0, 'domains': []}
    try:
        cookies = read_cookies_txt(path)
    except CookieFileError as exc:
        return {'status': 'Error', 'error': str(exc), 'cookies': []}
    domains = sorted({c['domain'].lstrip('.') for c in cookies})
    return {
        'status': 'Success',
        'path': str(Path(path).expanduser()),
        'cookies': cookies,
        'total': len(cookies),
        'domains': domains,
    }


def describe_cookies_txt(path: Optional[str]) -> str:
    """Return a short, secret-safe summary for status/log output."""
    result = validate_cookies_txt(path)
    if result.get('status') != 'Success':
        raise CookieFileError(result.get('error', 'invalid cookies.txt'))
    domains = result.get('domains') or []
    domain_text = ', '.join(domains[:3])
    if len(domains) > 3:
        domain_text += f' +{len(domains) - 3}'
    return f'{result.get("total", 0)} cookie(s)' + (
        f' for {domain_text}' if domain_text else ''
    )


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
