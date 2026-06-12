import gzip
import json
import re
import threading
import time
import zlib
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse

from core.site_map import summarize as _summarize_site_map
from utils.browser_utils import SessionBuilder


class SiteContentCapture:
    """Сканер структуры сайта с сохранением HTML-страниц"""

    def __init__(self):
        self.base_url: Optional[str] = None
        self.max_pages: int = 50
        self.output_dir: Optional[Path] = None
        self.visited: set = set()
        self.captured: List[Dict] = []
        self._site_map: List[Dict] = []   # every visited URL + its HTTP status
        self.progress_callback: Optional[Callable] = None
        self._profile: str = 'chrome_windows'
        self._delay: float = 0.5   # polite pause between page fetches (seconds)
        self._cancel = threading.Event()

    def cancel(self):
        """Signal the capture loop to stop at the next page boundary."""
        self._cancel.set()

    def configure(self, url: str, output_dir: str, max_pages: int = 50,
                  profile: str = 'chrome_windows', delay: float = 0.5):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.base_url = url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_pages = max_pages
        self._profile = profile
        self._delay = max(0.0, delay)
        self.visited.clear()
        self.captured.clear()
        self._site_map.clear()
        self._cancel.clear()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _fetch(self, url: str) -> Tuple[Optional[int], Optional[str]]:
        """Fetch ``url`` → ``(status, html)``.

        ``status`` is the HTTP code the server returned — including 4xx/5xx
        (captured so the site map can colour them) — or ``None`` on a transport
        error/timeout. ``html`` is the decoded body for a successful page, else
        ``None``.
        """
        try:
            session = SessionBuilder(self._profile)
            req = session.make_request(url)
            opener = session.build_opener()
            with opener.open(req, timeout=15) as r:
                raw = r.read()
                status = getattr(r, 'status', None) or r.getcode()
                enc = r.headers.get('Content-Encoding', '').lower().strip()
                if enc == 'gzip' or (not enc and raw[:2] == b'\x1f\x8b'):
                    raw = gzip.decompress(raw)
                elif enc == 'deflate':
                    try:
                        raw = zlib.decompress(raw)
                    except zlib.error:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                return status, raw.decode('utf-8', errors='ignore')
        except HTTPError as e:
            return e.code, None        # 4xx/5xx — keep the code for the site map
        except Exception:
            return None, None          # transport error / timeout — no status

    def _extract_links(self, html: str, base: str) -> List[str]:
        links = re.findall(r'href=["\']([^"\']+)["\']', html)
        base_domain = urlparse(base).netloc
        result = []
        for link in links:
            full = urljoin(base, link)
            parsed = urlparse(full)
            if parsed.netloc == base_domain and parsed.scheme in ('http', 'https'):
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean not in self.visited:
                    result.append(clean)
        return result

    def _save_page(self, url: str, html: str) -> str:
        parsed = urlparse(url)
        path = parsed.path.strip('/').replace('/', '_') or 'index'
        filename = f"{path}.html"
        filepath = self.output_dir / filename
        filepath.write_text(html, encoding='utf-8')
        return str(filepath)

    def run_capture(self) -> Dict:
        result = {
            'base_url': self.base_url,
            'pages_captured': 0,
            'files': [],
            'errors': []
        }

        if not self.base_url:
            result['error'] = 'No URL set'
            return result

        queue = [self.base_url]

        while queue and len(self.captured) < self.max_pages:
            if self._cancel.is_set():
                result['cancelled'] = True
                if self.progress_callback:
                    self.progress_callback("Отменено пользователем")
                break
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            if self.progress_callback:
                self.progress_callback(f"Сканирую: {url}")

            status, html = self._fetch(url)
            if not html:
                result['errors'].append(url)
                self._site_map.append({'url': url, 'status': status})
                continue

            saved = self._save_page(url, html)
            self.captured.append({'url': url, 'file': saved, 'status': status})
            self._site_map.append({'url': url, 'status': status, 'file': saved})
            result['files'].append(saved)

            new_links = self._extract_links(html, url)
            queue.extend(new_links[:10])
            if self._delay:
                time.sleep(self._delay)

        result['pages_captured'] = len(self.captured)

        # Visual site map: every visited URL (saved pages + error pages) with
        # its HTTP status, plus a per-status-group summary for the report/GUI.
        result['site_map'] = list(self._site_map)
        result['status_summary'] = _summarize_site_map(self._site_map)

        map_path = self.output_dir / 'site_map.json'
        map_path.write_text(
            json.dumps(self._site_map, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )

        return result
