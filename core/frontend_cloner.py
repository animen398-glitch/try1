import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from core.anti_detect_engine import AntiDetectSession


# Asset subdir by extension
_EXT_MAP: Dict[str, str] = {
    '.css': 'css', '.js': 'js',
    '.png': 'img', '.jpg': 'img', '.jpeg': 'img', '.gif': 'img',
    '.webp': 'img', '.svg': 'img', '.ico': 'img', '.bmp': 'img',
    '.woff': 'fonts', '.woff2': 'fonts', '.ttf': 'fonts',
    '.eot': 'fonts', '.otf': 'fonts',
}

# Extensions to treat as downloadable assets (not HTML pages)
_ASSET_EXTS: Set[str] = set(_EXT_MAP.keys())

# --- HTML patterns -------------------------------------------------------
# href/src single-pass: captures the quote, URL, closing quote
_HREF_RE = re.compile(r'(href=["\'])([^"\']+)(["\'])', re.IGNORECASE)
_SRC_RE  = re.compile(r'(src=["\'])([^"\']+)(["\'])',  re.IGNORECASE)
# srcset="url 1x, url2 2x"
_SRCSET_RE = re.compile(r'(srcset=["\'])([^"\']+)(["\'])', re.IGNORECASE)
# inline style url() and <style> blocks
_URL_RE = re.compile(r'(url\(\s*["\']?)([^"\')\s]+)(["\']?\s*\))', re.IGNORECASE)
# CSS @import url(...) or @import "..."
_IMPORT_RE = re.compile(
    r'(@import\s+(?:url\(\s*["\']?|["\']))([^"\')\s]+)(["\']?\s*\)?)', re.IGNORECASE
)


class FrontendCloner:
    """
    Downloads all CSS/JS/image/font assets referenced by captured HTML pages
    and rewrites every URL to a relative local path, producing fully
    self-contained offline copies.

    Integration: uses AntiDetectSession for all network fetches (rotating UA,
    cookie persistence, exponential-backoff retry, transparent gzip decoding).
    """

    def __init__(self):
        self.source_dir: Optional[Path] = None
        self.output_dir: Optional[Path] = None
        self.progress_callback: Optional[Callable] = None
        self.page_progress_callback: Optional[Callable] = None
        self._session = AntiDetectSession()
        self._cache: Dict[str, str] = {}   # original_url -> relative_local_path
        self._failed: List[str] = []
        self._cancel = threading.Event()

    def cancel(self):
        """Signal the clone loop to stop at the next page boundary."""
        self._cancel.set()

    def configure(
        self,
        source_dir: str,
        output_dir: Optional[str] = None,
        profile: str = 'chrome_windows',
        rotate_ua: bool = True,
    ):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir) if output_dir else self.source_dir
        self._session.configure(profile=profile, rotate_ua=rotate_ua, retry_count=3)
        self._cache = {}
        self._failed = []
        self._cancel.clear()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def set_page_progress_callback(self, cb: Callable):
        """Register cb(current, total) for structured per-page progress.

        Emitted with (0, total) once the page count is known and (n, total)
        after each page boundary. Keeps progress reporting independent of the
        human-readable log wording, so the UI never has to parse log strings.
        """
        self.page_progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def _emit_page_progress(self, current: int, total: int):
        if self.page_progress_callback:
            self.page_progress_callback(current, total)

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _ext(url: str) -> str:
        return Path(urlparse(url).path).suffix.lower()

    @staticmethod
    def _subdir(url: str) -> str:
        return _EXT_MAP.get(FrontendCloner._ext(url), 'misc')

    @staticmethod
    def _is_asset(url: str) -> bool:
        return FrontendCloner._ext(url) in _ASSET_EXTS

    @staticmethod
    def _local_name(url: str) -> str:
        """Unique filename: original stem + 6-char hash + original extension."""
        parsed = urlparse(url)
        stem = Path(parsed.path).stem or 'asset'
        suffix = Path(parsed.path).suffix or '.bin'
        tag = hashlib.md5(url.encode()).hexdigest()[:6]
        return f"{stem}_{tag}{suffix}"

    # ------------------------------------------------------------ downloader

    def _download(self, url: str, base_url: str) -> Optional[str]:
        """
        Download one asset. Returns the relative path string
        (e.g. 'assets/css/style_a1b2c3.css') to use in HTML/CSS,
        or None when the asset should not be downloaded.
        """
        if not url:
            return None
        # Skip inline data, anchors, and already-local paths
        if url.startswith(('data:', '#', 'javascript:', 'mailto:')):
            return None
        if url.startswith('assets/') or '../assets/' in url:
            return url  # already localised from a previous pass

        full_url = urljoin(base_url, url) if not url.startswith(('http://', 'https://')) else url
        if not full_url.startswith(('http://', 'https://')):
            return None
        if not self._is_asset(full_url):
            return None

        if full_url in self._cache:
            return self._cache[full_url]

        subdir = self._subdir(full_url)
        local_name = self._local_name(full_url)
        asset_dir = self.output_dir / 'assets' / subdir
        asset_dir.mkdir(parents=True, exist_ok=True)
        asset_path = asset_dir / local_name

        raw = self._session.fetch_bytes(full_url)
        if raw is None:
            self._failed.append(full_url)
            return None

        # Reserve the cache entry BEFORE processing the body so a circular CSS
        # @import (a.css -> b.css -> a.css) resolves to this path instead of
        # recursing into a re-fetch of the same file forever.
        rel = f"assets/{subdir}/{local_name}"
        self._cache[full_url] = rel

        # CSS: rewrite nested url() / @import before saving
        if subdir == 'css':
            try:
                text = raw.decode('utf-8', errors='ignore')
                text = self._process_css(text, full_url, depth='css')
                asset_path.write_text(text, encoding='utf-8')
            except Exception:
                asset_path.write_bytes(raw)
        else:
            asset_path.write_bytes(raw)

        self._log(f"  [{subdir}] {local_name}")
        return rel

    # ----------------------------------------------------- CSS rewriter

    def _process_css(self, css: str, css_url: str, depth: str = 'css') -> str:
        """
        Rewrite url() and @import paths inside a CSS string.
        'depth' is always 'css', kept as parameter for clarity.
        Assets inside CSS land at assets/<type>/; relative to assets/css/
        they are accessed as ../<type>/filename.
        """
        def repl_url(m):
            prefix, asset_url, suffix = m.group(1), m.group(2), m.group(3)
            rel = self._download(asset_url, css_url)
            if rel is None:
                return m.group(0)
            # From assets/css/ up one level then into target subdir
            parts = rel.split('/')   # ['assets', 'img', 'logo_abc.png']
            css_rel = '../' + '/'.join(parts[1:])
            return f"{prefix}{css_rel}{suffix}"

        def repl_import(m):
            prefix, asset_url, suffix = m.group(1), m.group(2), m.group(3)
            rel = self._download(asset_url, css_url)
            if rel is None:
                return m.group(0)
            parts = rel.split('/')
            css_rel = '../' + '/'.join(parts[1:])
            return f"{prefix}{css_rel}{suffix}"

        css = _URL_RE.sub(repl_url, css)
        css = _IMPORT_RE.sub(repl_import, css)
        return css

    # ---------------------------------------------------- HTML rewriter

    def _process_html(self, html: str, page_url: str) -> str:
        """
        Rewrite all downloadable asset references in an HTML document to
        relative paths pointing to the local assets/ tree.
        """
        def repl_attr(m):
            prefix, url_val, suffix = m.group(1), m.group(2), m.group(3)
            rel = self._download(url_val, page_url)
            return f"{prefix}{rel if rel else url_val}{suffix}"

        def repl_srcset(m):
            prefix, val, suffix = m.group(1), m.group(2), m.group(3)
            parts = []
            for entry in val.split(','):
                tokens = entry.strip().split()
                if tokens:
                    rel = self._download(tokens[0], page_url)
                    tokens[0] = rel if rel else tokens[0]
                parts.append(' '.join(tokens))
            return f"{prefix}{', '.join(parts)}{suffix}"

        def repl_url(m):
            prefix, url_val, suffix = m.group(1), m.group(2), m.group(3)
            rel = self._download(url_val, page_url)
            return f"{prefix}{rel if rel else url_val}{suffix}"

        html = _HREF_RE.sub(repl_attr, html)
        html = _SRC_RE.sub(repl_attr, html)
        html = _SRCSET_RE.sub(repl_srcset, html)
        html = _URL_RE.sub(repl_url, html)
        return html

    # ----------------------------------------------------------------- public

    def clone(self) -> Dict:
        result: Dict = {
            'source_dir': str(self.source_dir),
            'output_dir': str(self.output_dir),
            'pages_processed': 0,
            'assets_downloaded': 0,
            'failed': [],
            'status': 'Not started',
        }

        if not self.source_dir or not self.source_dir.exists():
            result['status'] = 'Error: source directory not found'
            return result

        # Load site_map.json to resolve original URLs for relative asset paths
        url_map: Dict[str, str] = {}  # html_filename -> original_url
        site_map_path = self.source_dir / 'site_map.json'
        if site_map_path.exists():
            try:
                entries = json.loads(site_map_path.read_text(encoding='utf-8'))
                for entry in entries:
                    fname = Path(entry.get('file', '')).name
                    if fname:
                        url_map[fname] = entry.get('url', '')
            except Exception:
                pass

        html_files = list(self.source_dir.glob('*.html'))
        if not html_files:
            result['status'] = 'Warning: no HTML files found in source directory'
            return result

        total = len(html_files)
        self._log(f"HTML файлов для обработки: {total}")
        self._emit_page_progress(0, total)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for idx, html_file in enumerate(html_files):
            if self._cancel.is_set():
                result['cancelled'] = True
                self._log("Отменено пользователем")
                break
            page_url = url_map.get(html_file.name, '')
            if not page_url:
                self._log(f"Пропускаю (нет URL в site_map): {html_file.name}")
                self._emit_page_progress(idx + 1, total)
                continue

            self._log(f"Локализую: {html_file.name}")
            try:
                html = html_file.read_text(encoding='utf-8', errors='ignore')
                html = self._process_html(html, page_url)
                out_file = self.output_dir / html_file.name
                out_file.write_text(html, encoding='utf-8')
                result['pages_processed'] += 1
            except Exception as e:
                self._log(f"  Ошибка при обработке {html_file.name}: {e}")
                result['failed'].append(html_file.name)
            self._emit_page_progress(idx + 1, total)

        result['assets_downloaded'] = len(self._cache)
        result['failed'].extend(self._failed)
        if result.get('cancelled'):
            result['status'] = 'Cancelled'
        else:
            result['status'] = 'Success' if result['pages_processed'] > 0 else 'Warning: no pages processed'
        self._log(
            f"Готово: {result['pages_processed']} стр., "
            f"{result['assets_downloaded']} ассетов, "
            f"{len(self._failed)} ошибок загрузки"
        )
        return result
