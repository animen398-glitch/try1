import re
from typing import Any, Dict, List, Optional, Pattern, Union

DEFAULT_DB = 'data/registry.db'
CONTEXT_CHARS = 40  # символов контекста с каждой стороны от совпадения


class PatternAnalyser:
    """Поиск строковых паттернов (ключи/токены) в тексте с записью в DataRegistry.

    Принимает словарь {имя: regex}. Каждое совпадение сохраняется как запись
    типа 'pattern_match' с именем паттерна и окружающим контекстом в метаданных.
    """

    def __init__(self, patterns: Dict[str, Union[str, Pattern]],
                 data_registry=None, context_chars: int = CONTEXT_CHARS):
        self.patterns: Dict[str, Pattern] = {
            name: re.compile(p) if isinstance(p, str) else p
            for name, p in patterns.items()
        }
        self._data_registry = data_registry
        self.context_chars = context_chars

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
        """Найти все совпадения паттернов в тексте, записать и вернуть находки."""
        findings: List[Dict[str, Any]] = []
        if not text:
            return findings

        for name, pattern in self.patterns.items():
            for m in pattern.finditer(text):
                matched = m.group(0)
                start, end = m.start(), m.end()
                ctx_start = max(0, start - self.context_chars)
                ctx_end = min(len(text), end + self.context_chars)
                context = text[ctx_start:ctx_end]

                finding = {
                    'pattern': name,
                    'match': matched,
                    'start': start,
                    'end': end,
                    'context': context,
                }
                findings.append(finding)
                self._record_discovery(
                    source=source, data_type='pattern_match', content=matched,
                    metadata={'pattern': name, 'context': context,
                              'position': start},
                )

        return findings
