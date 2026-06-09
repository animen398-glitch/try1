import gzip
import http.cookiejar
import random
import time
import urllib.error
import urllib.request
from typing import Dict, Optional

from utils.cloudflare_tools import detect_cloudflare


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
]


class CloudflareSession:
    """
    Сессия с браузер-подобными заголовками для снижения ложных срабатываний
    Cloudflare при легитимных запросах к открытым ресурсам.
    """

    def __init__(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.user_agent = random.choice(USER_AGENTS)
        self.retry_count = 3
        self.retry_delay = 2.0

    def _build_headers(self) -> Dict[str, str]:
        return {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

    def fetch(self, url: str, timeout: int = 20) -> Optional[str]:
        """Выполняет запрос с повторными попытками при временных ошибках"""
        headers = self._build_headers()

        for attempt in range(self.retry_count):
            try:
                req = urllib.request.Request(url, headers=headers)
                with self.opener.open(req, timeout=timeout) as response:
                    content = response.read()
                    if response.headers.get('Content-Encoding') == 'gzip':
                        content = gzip.decompress(content)
                    return content.decode('utf-8', errors='ignore')

            except urllib.error.HTTPError as e:
                if e.code in (429, 503) and attempt < self.retry_count - 1:
                    wait = self.retry_delay * (attempt + 1) + random.uniform(0.5, 1.5)
                    time.sleep(wait)
                    continue
                return None
            except urllib.error.URLError:
                if attempt < self.retry_count - 1:
                    time.sleep(self.retry_delay)
                    continue
                return None
            except Exception:
                return None

        return None

    def is_cloudflare_protected(self, html: str) -> bool:
        return detect_cloudflare(html)
