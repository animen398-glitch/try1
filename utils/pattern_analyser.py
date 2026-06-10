import re
from typing import Any, Dict, List, Optional, Pattern, Union

from core.config import REGISTRY_DB
DEFAULT_DB = str(REGISTRY_DB)
CONTEXT_CHARS = 40  # символов контекста с каждой стороны от совпадения

# Канонический набор паттернов по умолчанию: секреты/токены + API-эндпоинты.
DEFAULT_PATTERNS: Dict[str, str] = {
    'google_api_key':  r'AIza[0-9A-Za-z\-_]{35}',
    'aws_access_key':  r'AKIA[0-9A-Z]{16}',
    'github_token':    r'ghp_[A-Za-z0-9]{36}',
    'slack_token':     r'xox[baprs]-[A-Za-z0-9\-]+',
    'bearer_token':    r'[Bb]earer\s+[A-Za-z0-9._\-]{20,}',
    'generic_secret':  r'(?:api[_\-]?key|apikey|api_token|access_token|secret_key)'
                       r'["\'\s:=]+[A-Za-z0-9_\-]{16,}',
    'api_endpoint':    r'(https?://[a-zA-Z0-9\.\-]+\.(?:com|org|net|io|me)/'
                       r'[a-zA-Z0-9\/\.\-\?&_]+(?:api|v[0-9]|graphql)'
                       r'[a-zA-Z0-9\/\.\-\?&_]*)',
    'relative_api_endpoint': r'/(?:api|v[0-9]|graphql)/[a-zA-Z0-9\/\.\-\?&_]+',
}

# Имена паттернов, чьи совпадения сохраняются как тип 'api_endpoint'.
ENDPOINT_PATTERN_NAMES = frozenset({'api_endpoint', 'relative_api_endpoint'})


class PatternAnalyser:
    """Поиск строковых паттернов (ключи/токены/эндпоинты) в тексте с записью в DataRegistry.

    Принимает словарь {имя: regex}. Секреты сохраняются как 'pattern_match',
    а совпадения API-эндпоинтов — как 'api_endpoint'. В метаданных сохраняются
    имя паттерна и окружающий контекст.
    """

    def __init__(self, patterns: Optional[Dict[str, Union[str, Pattern]]] = None,
                 data_registry=None, context_chars: int = CONTEXT_CHARS):
        source = patterns if patterns is not None else DEFAULT_PATTERNS
        self.patterns: Dict[str, Pattern] = {
            name: re.compile(p) if isinstance(p, str) else p
            for name, p in source.items()
        }
        self._data_registry = data_registry
        self.context_chars = context_chars

    @staticmethod
    def _data_type_for(name: str) -> str:
        return 'api_endpoint' if name in ENDPOINT_PATTERN_NAMES else 'pattern_match'

    def _record_discovery(self, source: str, data_type: str, content: str,
                          metadata: Optional[Dict] = None) -> None:
        """Сохранить находку в DataRegistry (не ломая анализ)."""
        try:
            if self._data_registry is None:
                from core.registry import DataRegistry
                self._data_registry = DataRegistry()
            self._data_registry.add_record(source, data_type, content, metadata)
        except Exception:
            pass

    def analyze(self, text: str, source: str) -> List[Dict[str, Any]]:
        """Найти совпадения паттернов в тексте, записать и вернуть находки.

        Одинаковые совпадения (имя паттерна + строка) в пределах одного вызова
        записываются один раз — это снижает шум и ложные срабатывания, особенно
        для повторяющихся путей эндпоинтов.
        """
        findings: List[Dict[str, Any]] = []
        if not text:
            return findings

        seen: set = set()
        for name, pattern in self.patterns.items():
            data_type = self._data_type_for(name)
            for m in pattern.finditer(text):
                matched = m.group(0)
                dedup_key = (name, matched)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                start, end = m.start(), m.end()
                ctx_start = max(0, start - self.context_chars)
                ctx_end = min(len(text), end + self.context_chars)
                context = text[ctx_start:ctx_end]

                finding = {
                    'pattern': name,
                    'data_type': data_type,
                    'match': matched,
                    'start': start,
                    'end': end,
                    'context': context,
                }
                findings.append(finding)
                self._record_discovery(
                    source=source, data_type=data_type, content=matched,
                    metadata={'pattern': name, 'context': context,
                              'position': start},
                )

        return findings
