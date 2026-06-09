import html as _html
import re
from typing import Any, Dict, Optional

from utils.browser_utils import SessionBuilder
from utils.pattern_analyser import PatternAnalyser

# Набор паттернов по умолчанию для поиска утечек ключей/токенов в контенте.
DEFAULT_PATTERNS = {
    'google_api_key':  r'AIza[0-9A-Za-z\-_]{35}',
    'aws_access_key':  r'AKIA[0-9A-Z]{16}',
    'github_token':    r'ghp_[A-Za-z0-9]{36}',
    'slack_token':     r'xox[baprs]-[A-Za-z0-9\-]+',
    'bearer_token':    r'[Bb]earer\s+[A-Za-z0-9._\-]{20,}',
    'generic_secret':  r'(?:api[_\-]?key|apikey|api_token|access_token|secret_key)'
                       r'["\'\s:=]+[A-Za-z0-9_\-]{16,}',
}

_SCRIPT_STYLE_RE = re.compile(r'<(script|style)[^>]*>.*?</\1>', re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r'<[^>]+>')
_WS_RE = re.compile(r'\s+')


class SiteExtractor:
    """Загрузка страницы, очистка HTML и автоматический анализ паттернов.

    Сырой HTML анализируется PatternAnalyser (ключи/токены чаще всего в скриптах),
    а вызывающему возвращается очищенный от тегов текст.
    """

    def __init__(self, patterns: Optional[Dict[str, str]] = None,
                 analyser: Optional[PatternAnalyser] = None,
                 data_registry=None, profile: str = 'chrome_windows',
                 timeout: int = 20):
        self.profile = profile
        self.timeout = timeout
        self.analyser = analyser or PatternAnalyser(
            patterns or DEFAULT_PATTERNS, data_registry=data_registry,
        )

    @staticmethod
    def strip_html(html: str) -> str:
        """Удалить скрипты/стили/теги и вернуть нормализованный текст."""
        text = _SCRIPT_STYLE_RE.sub(' ', html)
        text = _TAG_RE.sub(' ', text)
        text = _html.unescape(text)
        return _WS_RE.sub(' ', text).strip()

    def fetch_text(self, url: str) -> Dict[str, Any]:
        """Загрузить страницу, проанализировать паттерны, вернуть чистый текст.

        Ошибки сети/HTTP перехватываются — метод никогда не бросает исключение.
        """
        result: Dict[str, Any] = {
            'url': url, 'status': 'Not started',
            'http_status': None, 'text': '', 'findings': [],
        }

        try:
            import requests
        except ImportError as e:
            result['status'] = f'Error: missing dependency requests ({e}). ' \
                               'Install: pip install requests'
            return result

        try:
            session = requests.Session()
            session.headers.update(SessionBuilder(self.profile).get_headers())
            resp = session.get(url, timeout=self.timeout)
            result['http_status'] = resp.status_code
            resp.raise_for_status()

            raw_html = resp.text
            result['text'] = self.strip_html(raw_html)
            # Анализируем сырой HTML — токены обычно живут в <script>.
            result['findings'] = self.analyser.analyze(raw_html, source=url)
            result['patterns_found'] = len(result['findings'])
            result['status'] = 'Success'
        except requests.exceptions.RequestException as e:
            result['status'] = f'Error: {e}'
        except Exception as e:
            result['status'] = f'Error: {e}'

        return result
