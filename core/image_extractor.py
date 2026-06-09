import gzip
import re
import urllib.error
import zlib
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from utils.browser_utils import SessionBuilder


class ImageExtractor:
    """Извлечение и загрузка изображений со страницы"""

    def __init__(self):
        self.target_url: Optional[str] = None
        self.output_dir: Optional[Path] = None
        self.progress_callback: Optional[Callable] = None
        self._profile: str = 'chrome_windows'

    def configure(self, url: str, output_dir: str, profile: str = 'chrome_windows'):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.target_url = url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._profile = profile

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _fetch_html(self, url: str) -> Optional[str]:
        try:
            session = SessionBuilder(self._profile)
            req = session.make_request(url)
            opener = session.build_opener()
            with opener.open(req, timeout=15) as r:
                raw = r.read()
                enc = r.headers.get('Content-Encoding', '').lower().strip()
                if enc == 'gzip' or (not enc and raw[:2] == b'\x1f\x8b'):
                    raw = gzip.decompress(raw)
                elif enc == 'deflate':
                    try:
                        raw = zlib.decompress(raw)
                    except zlib.error:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                return raw.decode('utf-8', errors='ignore')
        except Exception:
            return None

    def _find_image_urls(self, html: str) -> List[str]:
        patterns = [
            r'src=["\']([^"\']+\.(?:png|jpg|jpeg|gif|svg|webp|bmp)(?:\?[^"\']*)?)["\']',
            r'href=["\']([^"\']+\.(?:png|jpg|jpeg|gif|svg|webp|bmp))["\']',
            r'content=["\']([^"\']+\.(?:png|jpg|jpeg|gif|svg|webp|bmp))["\']',
        ]
        urls = set()
        for pattern in patterns:
            for match in re.findall(pattern, html, re.IGNORECASE):
                full_url = urljoin(self.target_url, match.split('?')[0])
                if full_url.startswith(('http://', 'https://')):
                    urls.add(full_url)
        return list(urls)

    def _download_image(self, url: str) -> Optional[str]:
        parsed = urlparse(url)
        filename = Path(parsed.path).name
        if not filename or '.' not in filename:
            filename = 'image_' + str(abs(hash(url)))[-8:] + '.jpg'

        filepath = self.output_dir / filename
        counter = 1
        stem = filepath.stem
        while filepath.exists():
            filepath = self.output_dir / f"{stem}_{counter}{filepath.suffix}"
            counter += 1

        try:
            session = SessionBuilder(self._profile).with_custom_header('Referer', self.target_url)
            req = session.make_request(url)
            opener = session.build_opener()
            with opener.open(req, timeout=20) as r:
                filepath.write_bytes(r.read())
            return str(filepath)
        except Exception:
            return None

    def run_extraction(self) -> Dict:
        result = {
            'url': self.target_url,
            'found': 0,
            'downloaded': 0,
            'files': [],
            'failed': []
        }

        if not self.target_url:
            result['error'] = 'No URL set'
            return result

        if self.progress_callback:
            self.progress_callback(f"Загружаю страницу: {self.target_url}")

        html = self._fetch_html(self.target_url)
        if not html:
            result['error'] = 'Failed to fetch page'
            return result

        image_urls = self._find_image_urls(html)
        result['found'] = len(image_urls)

        for url in image_urls:
            if self.progress_callback:
                self.progress_callback(f"Загружаю: {Path(urlparse(url).path).name}")

            saved = self._download_image(url)
            if saved:
                result['files'].append(saved)
                result['downloaded'] += 1
            else:
                result['failed'].append(url)

        return result
