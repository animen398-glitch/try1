import gzip
import http.cookiejar
import random
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional


_PROFILES: Dict[str, Dict[str, str]] = {
    'chrome_windows': {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
    },
    'firefox_windows': {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) '
            'Gecko/20100101 Firefox/122.0'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
    },
    'safari_mac': {
        'User-Agent': (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) '
            'AppleWebKit/605.1.15 (KHTML, like Gecko) '
            'Version/17.2 Safari/605.1.15'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    },
    'chrome_linux': {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    },
}

_PROFILE_NAMES: List[str] = list(_PROFILES.keys())


class AntiDetectSession:
    """
    Browser-fingerprint-aware HTTP session.
    Provides rotating User-Agents, persistent cookies per session,
    exponential-backoff retries on 429/503, and transparent gzip decoding.
    """

    def __init__(self):
        self.profile: str = 'chrome_windows'
        self.proxies: Optional[Dict[str, str]] = None
        self._rotate_ua: bool = False
        self._retry_count: int = 3
        self._base_delay: float = 1.5
        self._cookie_jar = http.cookiejar.CookieJar()

    def configure(
        self,
        profile: str = 'chrome_windows',
        proxies: Optional[Dict[str, str]] = None,
        rotate_ua: bool = False,
        retry_count: int = 3,
        base_delay: float = 1.5,
    ):
        self.profile = profile if profile in _PROFILES else 'chrome_windows'
        self.proxies = proxies
        self._rotate_ua = rotate_ua
        self._retry_count = retry_count
        self._base_delay = base_delay
        self._cookie_jar = http.cookiejar.CookieJar()

    # ----------------------------------------------------------------- internal

    def _headers(self) -> Dict[str, str]:
        key = random.choice(_PROFILE_NAMES) if self._rotate_ua else self.profile
        return dict(_PROFILES[key])

    def _opener(self) -> urllib.request.OpenerDirector:
        handlers: list = [urllib.request.HTTPCookieProcessor(self._cookie_jar)]
        if self.proxies:
            handlers.append(urllib.request.ProxyHandler(self.proxies))
        return urllib.request.build_opener(*handlers)

    @staticmethod
    def _decompress(raw: bytes, response) -> bytes:
        if response.headers.get('Content-Encoding', '') == 'gzip':
            return gzip.decompress(raw)
        return raw

    def _backoff(self, attempt: int):
        wait = self._base_delay * (2 ** attempt) + random.uniform(0.2, 0.8)
        time.sleep(wait)

    # ------------------------------------------------------------------ public

    def fetch(self, url: str, timeout: int = 20) -> Optional[str]:
        """Fetch URL, return decoded text or None on persistent failure."""
        opener = self._opener()
        for attempt in range(self._retry_count):
            try:
                req = urllib.request.Request(url, headers=self._headers())
                with opener.open(req, timeout=timeout) as r:
                    raw = self._decompress(r.read(), r)
                    return raw.decode('utf-8', errors='ignore')
            except urllib.error.HTTPError as e:
                if e.code in (429, 503) and attempt < self._retry_count - 1:
                    self._backoff(attempt)
                    if self._rotate_ua:
                        opener = self._opener()
                    continue
                return None
            except urllib.error.URLError:
                if attempt < self._retry_count - 1:
                    time.sleep(self._base_delay)
                    continue
                return None
            except Exception:
                return None
        return None

    def fetch_bytes(self, url: str, timeout: int = 20) -> Optional[bytes]:
        """Fetch URL, return raw bytes or None on persistent failure."""
        opener = self._opener()
        for attempt in range(self._retry_count):
            try:
                req = urllib.request.Request(url, headers=self._headers())
                with opener.open(req, timeout=timeout) as r:
                    return self._decompress(r.read(), r)
            except urllib.error.HTTPError as e:
                if e.code in (429, 503) and attempt < self._retry_count - 1:
                    self._backoff(attempt)
                    continue
                return None
            except Exception:
                return None
        return None
