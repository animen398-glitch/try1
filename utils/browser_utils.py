import http.cookiejar
import random
import urllib.request
from typing import Dict


BROWSER_HEADERS: Dict[str, Dict[str, str]] = {
    'chrome_windows': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    },
    'firefox_windows': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    },
    'safari_mac': {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    },
}


class SessionBuilder:
    """Конструктор HTTP-сессий с кастомными браузерными заголовками"""

    def __init__(self, profile: str = 'chrome_windows'):
        self.headers = BROWSER_HEADERS.get(profile, BROWSER_HEADERS['chrome_windows']).copy()

    def with_custom_header(self, key: str, value: str) -> 'SessionBuilder':
        self.headers[key] = value
        return self

    def with_random_agent(self) -> 'SessionBuilder':
        profile = random.choice(list(BROWSER_HEADERS.keys()))
        self.headers['User-Agent'] = BROWSER_HEADERS[profile]['User-Agent']
        return self

    def build_opener(self) -> urllib.request.OpenerDirector:
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def make_request(self, url: str) -> urllib.request.Request:
        return urllib.request.Request(url, headers=self.headers)

    def get_headers(self) -> Dict[str, str]:
        return self.headers.copy()
