from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit, urlunsplit

from core.config import REGISTRY_DB
DEFAULT_DB = str(REGISTRY_DB)


class EndpointIndex:
    """Нормализация и дедупликация записей api_endpoint в DataRegistry.

    Эндпоинты записываются многократно (по странице/скрипту), поэтому этот
    индекс сводит их к уникальному списку с агрегатами: число вхождений,
    страницы-источники и сработавшие паттерны.
    """

    DATA_TYPE = 'api_endpoint'

    def __init__(self, registry=None, db_path: Union[str, Path] = DEFAULT_DB):
        self._registry = registry
        self._db_path = db_path

    def _records(self) -> List[Dict[str, Any]]:
        if self._registry is None:
            from core.registry import DataRegistry
            self._registry = DataRegistry(db_path=str(self._db_path))
        return self._registry.get_records(data_type=self.DATA_TYPE, limit=1_000_000)

    @staticmethod
    def normalize(endpoint: str) -> str:
        """Привести эндпоинт к каноническому виду.

        Отбрасывает фрагмент и query-строку, убирает завершающий слэш,
        приводит схему/хост к нижнему регистру (путь сохраняет регистр).
        """
        e = (endpoint or '').strip()
        if not e:
            return ''
        e = e.split('#', 1)[0].split('?', 1)[0]
        parts = urlsplit(e)
        if parts.scheme:  # абсолютный URL
            path = parts.path.rstrip('/') or '/'
            return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, '', ''))
        return e.rstrip('/') if len(e) > 1 else e

    def get_unique_endpoints(self) -> List[Dict[str, Any]]:
        """Уникальные нормализованные эндпоинты, по убыванию числа вхождений."""
        groups: Dict[str, Dict[str, Any]] = {}
        for rec in self._records():
            norm = self.normalize(rec.get('content', ''))
            if not norm:
                continue
            g = groups.get(norm)
            if g is None:
                g = {'endpoint': norm, 'count': 0,
                     'sources': set(), 'patterns': set()}
                groups[norm] = g
            g['count'] += 1
            source = rec.get('source')
            if source:
                g['sources'].add(source)
            meta = rec.get('metadata')
            if isinstance(meta, dict) and meta.get('pattern'):
                g['patterns'].add(meta['pattern'])

        result = [
            {
                'endpoint': g['endpoint'],
                'count': g['count'],
                'source_count': len(g['sources']),
                'sources': sorted(g['sources']),
                'patterns': sorted(g['patterns']),
            }
            for g in groups.values()
        ]
        result.sort(key=lambda x: (-x['count'], x['endpoint']))
        return result

    def get_summary(self) -> Dict[str, int]:
        """Сводка: всего записей эндпоинтов и сколько из них уникальны."""
        unique = self.get_unique_endpoints()
        return {
            'total_records': sum(g['count'] for g in unique),
            'unique_endpoints': len(unique),
        }
