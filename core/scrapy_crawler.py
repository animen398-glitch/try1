"""core/scrapy_crawler.py

Subprocess-based Scrapy deep crawler — the GUI-side wrapper around the child
spider in ``core/_scrapy_spider.py``.

Why a subprocess: Scrapy embeds the Twisted reactor, which cannot share Qt's
event loop and cannot be restarted within one interpreter. Running each crawl
in a fresh child process sidesteps both problems and keeps Scrapy (a heavy,
optional dependency) out of the GUI process entirely — this module detects
availability with ``find_spec`` and never imports ``scrapy`` itself.

Pure backend (no Qt) doing blocking I/O: call :meth:`crawl` from a worker
thread, the way the GUI does via ``window._run_async``.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from core.features import has_scrapy
from core.paths import get_path_manager
from utils.subprocess_utils import run_hidden

_RUNNER = Path(__file__).resolve().parent / '_scrapy_spider.py'


class ScrapyCrawler:
    """Run a bounded same-domain Scrapy crawl in a child process."""

    def __init__(self, max_pages: int = 50, depth: int = 2,
                 timeout: int = 120, obey_robots: bool = True,
                 user_agent: Optional[str] = None):
        self.max_pages = max_pages
        self.depth = depth
        self.timeout = timeout
        self.obey_robots = obey_robots
        self.user_agent = user_agent
        self.progress_callback: Optional[Callable] = None
        self.cancel_event = None

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def set_cancel_event(self, ev) -> None:
        """Cooperative cancellation seam — a set token kills the crawl subprocess
        (and its tree) mid-run; partial pages already written are still returned."""
        self.cancel_event = ev

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    @staticmethod
    def is_available() -> bool:
        """True if Scrapy can be launched (detected without importing it)."""
        return has_scrapy()

    def crawl(self, url: str) -> Dict:
        """Crawl ``url`` and return ``{status, url, items, pages, ...}``.

        Degrades gracefully: a missing Scrapy, a non-zero exit, or a timeout all
        yield a structured result (partial items are still returned on timeout)
        rather than raising.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {'status': 'Error', 'url': url, 'items': [], 'pages': 0}

        if not self.is_available():
            result['error'] = (
                'scrapy not installed. Run: pip install "scrapy>=2.11,<3"')
            return result

        out_file = self._out_path(url)
        cmd = [
            sys.executable, str(_RUNNER), url,
            '--out', str(out_file),
            '--max-pages', str(self.max_pages),
            '--depth', str(self.depth),
        ]
        if self.user_agent:
            cmd += ['--user-agent', self.user_agent]
        if self.obey_robots:
            cmd.append('--obey-robots')

        self._log(f'[Scrapy] crawling {url} (≤{self.max_pages} pages, depth {self.depth})')
        truncated = False
        stderr_tail = ''
        t0 = time.monotonic()
        run_info: Dict = {}
        if self.cancel_event is not None:
            # Cancellable path — poll loop kills the whole tree on cancel/timeout.
            from utils.subprocess_utils import run_capture
            res = run_capture(cmd, timeout=self.timeout,
                              cancel_event=self.cancel_event)
            run_info = res
            stderr_tail = (res.get('stderr') or '')[-500:]
            truncated = bool(res.get('timed_out'))
            if res.get('cancelled'):
                result['error'] = 'crawl cancelled'
                self._log('[Scrapy] cancelled — returning partial results')
            elif res.get('error'):
                result['error'] = res['error']
            elif res.get('rc') not in (0, None):
                result['error'] = f'crawler exited {res.get("rc")}: {stderr_tail.strip()}'
        else:
            try:
                proc = run_hidden(
                    cmd, capture_output=True, text=True, timeout=self.timeout)
                stderr_tail = (proc.stderr or '')[-500:]
                run_info = {'rc': proc.returncode, 'stderr': proc.stderr or ''}
                if proc.returncode not in (0, None):
                    result['error'] = f'crawler exited {proc.returncode}: {stderr_tail.strip()}'
            except subprocess.TimeoutExpired as e:
                truncated = True
                run_info = {'timed_out': True}
                stderr_tail = (e.stderr or '')[-500:] if isinstance(e.stderr, str) else ''
                self._log(f'[Scrapy] timed out after {self.timeout}s — returning partial results')

        try:
            from utils.system_logger import journal_tool_run
            journal_tool_run('scrapy', cmd, run_info,
                             duration_ms=int((time.monotonic() - t0) * 1000))
        except Exception:
            pass

        items = self._read_feed(out_file)
        self._cleanup(out_file)

        if items or truncated or 'error' not in result:
            result['status'] = 'Success'
            result.pop('error', None)
        result['items'] = items
        result['pages'] = len(items)
        result['truncated'] = truncated
        if stderr_tail and result['status'] != 'Success':
            result['stderr'] = stderr_tail.strip()
        self._log(f'[Scrapy] done — {len(items)} pages crawled'
                  + (' (truncated)' if truncated else ''))
        return result

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _out_path(url: str) -> Path:
        netloc = urlparse(url).netloc.replace(':', '_') or 'site'
        name = f'scrapy_{netloc}_{int(time.time())}.jsonl'
        return get_path_manager().get_temp_path() / name

    @staticmethod
    def _read_feed(path: Path) -> List[Dict]:
        if not path.exists():
            return []
        items: List[Dict] = []
        try:
            for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass
        return items

    @staticmethod
    def _cleanup(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
