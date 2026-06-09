import hashlib
import mimetypes
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse

from utils.browser_utils import SessionBuilder
from utils.operation_registry import OperationRegistry

# Operation history shares the orchestrator's database so extractions appear in
# the GUI "История операций" tab alongside the other phases.
DEFAULT_DB = 'data/operations.db'
MIN_IMAGE_BYTES = 2048  # пропускаем иконки/мелкие изображения < 2KB


class ImageExtractor:
    """Извлечение изображений со страницы с дедупликацией и записью в реестр."""

    def __init__(self, registry: Optional[OperationRegistry] = None,
                 profile: str = 'chrome_windows',
                 min_bytes: int = MIN_IMAGE_BYTES, timeout: int = 20):
        self.registry = registry or OperationRegistry(db_path=DEFAULT_DB)
        self.profile = profile
        self.min_bytes = min_bytes
        self.timeout = timeout
        self.progress_callback: Optional[Callable] = None

    def set_progress_callback(self, cb: Callable) -> None:
        self.progress_callback = cb

    def _log(self, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(msg)

    def extract_images(self, target_url: str,
                       output_dir: Union[str, Path]) -> Dict:
        """Скачать изображения с target_url в output_dir.

        Мелкие изображения (< min_bytes) пропускаются, дубликаты отсеиваются
        по SHA-256 содержимого. Начало/итог операции пишутся в реестр.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        result: Dict = {
            'url': target_url, 'status': 'Not started',
            'found': 0, 'downloaded': 0,
            'skipped_small': 0, 'duplicates': 0,
            'failed': [], 'files': [],
        }
        op_id = self.registry.start(
            target=target_url, phase='image_extraction',
            output_dir=str(out_path), metadata={'min_bytes': self.min_bytes},
        )

        try:
            import requests
            from bs4 import BeautifulSoup
        except ImportError as e:
            msg = f'Missing dependency: {e}. Install: pip install requests beautifulsoup4'
            result['status'] = f'Error: {msg}'
            self.registry.finish(op_id, status='failed', error=msg)
            return result

        try:
            session = requests.Session()
            session.headers.update(SessionBuilder(self.profile).get_headers())

            self._log(f'Загружаю страницу: {target_url}')
            resp = session.get(target_url, timeout=self.timeout)
            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, 'html.parser')
            img_urls = self._collect_image_urls(soup, target_url)
            result['found'] = len(img_urls)
            self._log(f'Найдено ссылок на изображения: {len(img_urls)}')

            seen_hashes: set = set()
            for img_url in img_urls:
                try:
                    r = session.get(img_url, timeout=self.timeout)
                    r.raise_for_status()
                    content = r.content
                except Exception:
                    result['failed'].append(img_url)
                    continue

                if len(content) < self.min_bytes:
                    result['skipped_small'] += 1
                    continue

                digest = hashlib.sha256(content).hexdigest()
                if digest in seen_hashes:
                    result['duplicates'] += 1
                    continue
                seen_hashes.add(digest)

                fpath = self._unique_path(
                    out_path, img_url, digest,
                    r.headers.get('Content-Type', ''),
                )
                fpath.write_bytes(content)
                result['downloaded'] += 1
                result['files'].append(str(fpath))

            self._log(
                f"Загружено: {result['downloaded']} | "
                f"дубликатов: {result['duplicates']} | "
                f"мелких пропущено: {result['skipped_small']}"
            )
            result['status'] = 'Success'
            self.registry.finish(op_id, status='success')

        except Exception as e:
            result['status'] = f'Error: {e}'
            self.registry.finish(op_id, status='failed', error=str(e))

        return result

    @staticmethod
    def _collect_image_urls(soup, base_url: str) -> List[str]:
        """Собрать абсолютные URL из <img src>, lazy-атрибутов и srcset."""
        found: List[str] = []
        seen: set = set()

        def add(raw: Optional[str]):
            if not raw:
                return
            raw = raw.strip()
            if not raw or raw.startswith('data:'):
                return
            absolute = urljoin(base_url, raw)
            if absolute not in seen:
                seen.add(absolute)
                found.append(absolute)

        for img in soup.find_all('img'):
            add(img.get('src'))
            add(img.get('data-src'))
            srcset = img.get('srcset') or img.get('data-srcset')
            if srcset:
                # каждый кандидат: "<url> <descriptor>", берём только url
                for candidate in srcset.split(','):
                    add(candidate.strip().split()[0] if candidate.strip() else None)

        for source in soup.find_all('source'):
            srcset = source.get('srcset')
            if srcset:
                for candidate in srcset.split(','):
                    add(candidate.strip().split()[0] if candidate.strip() else None)

        return found

    @staticmethod
    def _unique_path(out_dir: Path, img_url: str, digest: str,
                     content_type: str) -> Path:
        name = Path(urlparse(img_url).path).name
        name = re.sub(r'[^\w.\-]', '_', name)
        if not name or '.' not in name:
            ext = mimetypes.guess_extension((content_type or '').split(';')[0].strip()) or '.img'
            name = f'{digest[:16]}{ext}'

        candidate = out_dir / name
        if candidate.exists():
            stem, suffix = candidate.stem, candidate.suffix
            candidate = out_dir / f'{stem}_{digest[:8]}{suffix}'
        return candidate
