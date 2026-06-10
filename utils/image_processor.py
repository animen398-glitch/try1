import hashlib
import http.cookiejar
import mimetypes
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse, urlunparse

from utils.browser_utils import SessionBuilder
from utils.operation_registry import OperationRegistry

# Operation history shares the orchestrator's database so extractions appear in
# the GUI "История операций" tab alongside the other phases.
from core.config import OPERATIONS_DB
DEFAULT_DB = str(OPERATIONS_DB)
MIN_IMAGE_BYTES = 2048  # пропускаем иконки/мелкие изображения < 2KB

# Query params that CDNs use to downscale / watermark images. Stripping them
# requests the original, full-resolution, un-watermarked asset.
_RESIZE_PARAMS = {
    'w', 'h', 'width', 'height', 'resize', 'fit', 'crop', 'quality', 'q',
    'dpr', 'watermark', 'wm', 'mark', 'size', 's', 'fm',
}
# Instagram/Facebook CDN path segments like /s640x640/ or /p1080x1080/.
_CDN_SIZE_SEG = re.compile(r'/[sp]\d+x\d+/')
# Hosts whose media is JS/login-gated — delegate to yt-dlp's native extractor.
_GALLERY_HOSTS = ('instagram.com', 'tiktok.com', 'pinterest.', 'twitter.com', 'x.com')


def _prefer_original(url: str) -> str:
    """Return a higher-resolution / un-watermarked variant of an image URL.

    Drops known resize/watermark query params and CDN size path segments so
    the original asset is fetched instead of a scaled, watermarked thumbnail.
    """
    parsed = urlparse(url)
    # Strip resize params from the query string.
    if parsed.query:
        kept = [
            kv for kv in parsed.query.split('&')
            if kv and kv.split('=', 1)[0].lower() not in _RESIZE_PARAMS
        ]
        parsed = parsed._replace(query='&'.join(kept))
    # Strip CDN size segments from the path.
    path = _CDN_SIZE_SEG.sub('/', parsed.path)
    parsed = parsed._replace(path=path)
    return urlunparse(parsed)


class ImageExtractor:
    """Извлечение изображений со страницы с дедупликацией и записью в реестр.

    Выбирает оригинальное разрешение (срезает resize/watermark-параметры),
    поддерживает сессионные cookies и делегирует Instagram/соцсети yt-dlp.
    """

    def __init__(self, registry: Optional[OperationRegistry] = None,
                 data_registry=None,
                 profile: str = 'chrome_windows',
                 min_bytes: int = MIN_IMAGE_BYTES, timeout: int = 20,
                 cookies: Optional[str] = None,
                 prefer_original: bool = True):
        self.registry = registry or OperationRegistry(db_path=DEFAULT_DB)
        self._data_registry = data_registry
        self.profile = profile
        self.min_bytes = min_bytes
        self.timeout = timeout
        self.cookies = cookies               # path to a Netscape cookies.txt
        self.prefer_original = prefer_original
        self.progress_callback: Optional[Callable] = None

    def set_progress_callback(self, cb: Callable) -> None:
        self.progress_callback = cb

    def _log(self, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(msg)

    def _record_data(self, source: str, data_type: str, content: str,
                     metadata: Optional[Dict] = None) -> None:
        """Сохранить найденный контент в DataRegistry (не ломая основную операцию)."""
        try:
            if self._data_registry is None:
                from core.registry import DataRegistry
                self._data_registry = DataRegistry()
            self._data_registry.add_record(source, data_type, content, metadata)
        except Exception as e:
            self._log(f'Не удалось записать в DataRegistry: {e}')

    @staticmethod
    def _is_gallery_host(url: str) -> bool:
        host = urlparse(url).netloc.lower()
        return any(h in host for h in _GALLERY_HOSTS)

    def extract_images(self, target_url: str,
                       output_dir: Union[str, Path]) -> Dict:
        """Скачать изображения с target_url в output_dir.

        Для Instagram/соцсетей контент берётся через yt-dlp (оригинал без
        водяных знаков). Для обычных страниц — парсинг HTML с выбором
        оригинального разрешения, пропуском мелких (< min_bytes) и дедупом
        по SHA-256. Начало/итог операции пишутся в реестр.
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

        # Instagram / social media: direct scraping is login-gated, so let
        # yt-dlp's extractor fetch the original media (no watermark).
        if self._is_gallery_host(target_url):
            return self._extract_via_ytdlp(target_url, out_path, op_id, result)

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
            self._load_cookies(session)

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
                self._record_data(
                    source=target_url, data_type='image', content=str(fpath),
                    metadata={'source_url': img_url, 'bytes': len(content),
                              'sha256': digest},
                )

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

    def _load_cookies(self, session) -> None:
        """Load a Netscape cookies.txt into the requests session, if given."""
        if not self.cookies:
            return
        try:
            jar = http.cookiejar.MozillaCookieJar()
            jar.load(self.cookies, ignore_discard=True, ignore_expires=True)
            session.cookies.update(jar)
            self._log(f'Загружены cookies: {self.cookies}')
        except Exception as e:
            self._log(f'Не удалось загрузить cookies ({self.cookies}): {e}')

    def _extract_via_ytdlp(self, url: str, out_path: Path, op_id,
                           result: Dict) -> Dict:
        """Download original media for gallery/social hosts via yt-dlp."""
        if shutil.which('yt-dlp') is None:
            msg = ('yt-dlp требуется для Instagram/соцсетей. '
                   'Install: pip install yt-dlp')
            result['status'] = f'Error: {msg}'
            self.registry.finish(op_id, status='failed', error=msg)
            return result

        before = {p for p in out_path.glob('**/*') if p.is_file()}
        cmd = [
            'yt-dlp', '--no-playlist',
            '--output', str(out_path / '%(title).80s_%(id)s.%(ext)s'),
            url,
        ]
        if self.cookies:
            cmd += ['--cookies', str(self.cookies)]

        self._log(f'Instagram/соцсеть → yt-dlp: {url}')
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=max(self.timeout, 120))
        except subprocess.TimeoutExpired:
            result['status'] = 'Error: timeout'
            self.registry.finish(op_id, status='failed', error='timeout')
            return result

        new_files = [p for p in out_path.glob('**/*')
                     if p.is_file() and p not in before]
        for p in new_files:
            result['files'].append(str(p))
            self._record_data(source=url, data_type='image', content=str(p),
                              metadata={'via': 'yt-dlp'})
        result['found'] = result['downloaded'] = len(new_files)

        if new_files:
            result['status'] = 'Success'
            self.registry.finish(op_id, status='success')
            self._log(f'Скачано через yt-dlp: {len(new_files)} файл(ов)')
        else:
            error = (proc.stderr or 'no media downloaded')[:500]
            result['status'] = f'Error: {error}'
            self.registry.finish(op_id, status='failed', error=error)
        return result

    def _collect_image_urls(self, soup, base_url: str) -> List[str]:
        """Собрать абсолютные URL из <img src>, lazy-атрибутов и srcset.

        Из srcset берётся кандидат с наибольшим дескриптором (макс. разрешение),
        а каждый URL приводится к оригинальному виду через _prefer_original.
        """
        found: List[str] = []
        seen: set = set()

        def add(raw: Optional[str]):
            if not raw:
                return
            raw = raw.strip()
            if not raw or raw.startswith('data:'):
                return
            absolute = urljoin(base_url, raw)
            if self.prefer_original:
                absolute = _prefer_original(absolute)
            if absolute not in seen:
                seen.add(absolute)
                found.append(absolute)

        for img in soup.find_all('img'):
            add(img.get('src'))
            add(img.get('data-src'))
            srcset = img.get('srcset') or img.get('data-srcset')
            if srcset:
                add(self._largest_srcset(srcset))

        for source in soup.find_all('source'):
            srcset = source.get('srcset')
            if srcset:
                add(self._largest_srcset(srcset))

        return found

    @staticmethod
    def _largest_srcset(srcset: str) -> Optional[str]:
        """Pick the highest-resolution URL from a srcset attribute."""
        best: Optional[str] = None
        best_score = -1.0
        for candidate in srcset.split(','):
            tokens = candidate.strip().split()
            if not tokens:
                continue
            url = tokens[0]
            score = 0.0
            if len(tokens) > 1:
                descriptor = tokens[1].lower().rstrip('wx')
                try:
                    score = float(descriptor)
                except ValueError:
                    score = 0.0
            if score > best_score:
                best_score = score
                best = url
        return best

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
