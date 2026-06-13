from pathlib import Path
from typing import Any, Dict, List, Union

from core.config import REGISTRY_DB
DEFAULT_DB = str(REGISTRY_DB)


class DataViewer:
    """Чтение и агрегация записей DataRegistry для GUI-дашборда.

    Тонкая обёртка над DataRegistry: декодирование JSON-метаданных и сортировка
    обеспечиваются самим реестром (SQLiteStore._row_to_dict / ORDER BY id DESC).
    """

    # Соответствие "ключ дашборда -> data_type", который пишут модули обнаружения.
    SUMMARY_TYPES = {
        'subdomains': 'subdomain',
        'ips': 'ip_address',
        'images': 'image',
        'videos': 'video',
        'patterns': 'pattern_match',
        'api_endpoints': 'api_endpoint',
        'takeovers': 'takeover',
        'source_maps': 'source_map',
    }

    def __init__(self, registry=None, db_path: Union[str, Path] = DEFAULT_DB):
        if registry is None:
            from core.registry import DataRegistry
            registry = DataRegistry(db_path=db_path)
        self.registry = registry

    def get_summary(self) -> Dict[str, int]:
        """Счётчики по типам найденных активов (+ общий total)."""
        summary = {
            key: self.registry.count(dtype)
            for key, dtype in self.SUMMARY_TYPES.items()
        }
        summary['total'] = self.registry.count()
        return summary

    def get_recent_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Последние записи реестра, новые сверху (по времени добавления)."""
        return self.registry.get_records(limit=limit)

    def get_by_type(self, data_type: str) -> List[Dict[str, Any]]:
        """Все записи указанного типа, новые сверху."""
        return self.registry.get_records(data_type=data_type, limit=1_000_000)
