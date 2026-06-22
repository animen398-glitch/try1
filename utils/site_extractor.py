import html as _html
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from utils.browser_utils import SessionBuilder
from utils.pattern_analyser import PatternAnalyser, DEFAULT_PATTERNS

_SCRIPT_STYLE_RE = re.compile(r'<(script|style)[^>]*>.*?</\1>', re.IGNORECASE | re.DOTALL)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
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
        """Удалить скрипты/стили/теги и вернуть нормализованный текст.

        Degrade-not-raise: a non-string (e.g. ``None`` from a failed fetch) yields
        ''. so a caller never crashes on a bad body."""
        if not isinstance(html, str):
            return ''
        text = _SCRIPT_STYLE_RE.sub(' ', html)
        text = _TAG_RE.sub(' ', text)
        text = _html.unescape(text)
        return _WS_RE.sub(' ', text).strip()

    @staticmethod
    def _extract_script_urls(html: str, base_url: str) -> List[str]:
        """Собрать абсолютные URL внешних скриптов из <script src="...">."""
        if not isinstance(html, str):
            return []
        urls: List[str] = []
        seen: set = set()
        for m in _SCRIPT_SRC_RE.finditer(html):
            src = m.group(1).strip()
            if not src:
                continue
            absolute = urljoin(base_url, src)  # корректно разрешает относительные пути
            if absolute not in seen:
                seen.add(absolute)
                urls.append(absolute)
        return urls

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

            # Обнаружение и анализ внешних JS-скриптов.
            script_urls = self._extract_script_urls(raw_html, url)
            result['scripts_found'] = len(script_urls)
            analyzed = 0
            for js_url in script_urls:
                try:
                    jr = session.get(js_url, timeout=self.timeout)
                    jr.raise_for_status()
                    js_content = jr.text
                except Exception:
                    # Сбой загрузки одного скрипта не должен ломать процесс.
                    continue
                # Attribute findings to the script they came from, not the page,
                # so the leak's provenance points at the exact external JS file.
                result['findings'].extend(self.analyser.analyze(js_content, js_url))
                analyzed += 1
            result['scripts_analyzed'] = analyzed

            result['patterns_found'] = len(result['findings'])
            result['status'] = 'Success'
        except requests.exceptions.RequestException as e:
            result['status'] = f'Error: {e}'
        except Exception as e:
            result['status'] = f'Error: {e}'

        return result
