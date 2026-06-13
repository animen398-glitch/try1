"""core/screenshot.py
Capture a full-page screenshot of a URL via headless Chromium (Playwright).

Optional / gated (architectural invariant I1): when Playwright isn't installed
this degrades gracefully — ``capture`` returns a status dict instead of raising,
and ``available()`` lets callers disable the feature up front (the same pattern
as dynamic_analyzer). It does blocking browser I/O, so call it from a worker
thread; reports link the saved PNG by *relative path* rather than base64-inlining
it, keeping the offline report small and self-contained (invariant I2).

Scope is deliberately just the screenshot — no OCR / "intelligence" (that was
rejected in the audit as unbounded, ML-dependency scope).
"""

import asyncio
import concurrent.futures
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse

from core.features import has_playwright

# Page-type signatures (Aquatone-style): a substring in the URL path/query maps
# it to a labelled page type, so a multi-page screenshot run captures the few
# pages that actually matter for triage rather than every crawled URL. Order is
# priority order — the first match wins.
PAGE_TYPES = (
    ('login',     ('login', 'signin', 'sign-in', 'log-in', 'auth', 'sso')),
    ('admin',     ('admin', 'wp-admin', 'administrator', 'cpanel', 'manage')),
    ('dashboard', ('dashboard', 'console', 'portal')),
    ('register',  ('register', 'signup', 'sign-up')),
    ('account',   ('account', 'profile', 'settings')),
    ('api',       ('/api', 'graphql', 'swagger', 'openapi')),
)
# Common sensitive paths to probe even if the crawl never linked them (each is
# screenshotted; a 4xx/5xx still yields an informative "not reachable" row).
COMMON_PATHS = (('login', '/login'), ('admin', '/admin'),
                ('dashboard', '/dashboard'))
# A multi-page run is bounded so the opt-in phase stays quick and polite.
DEFAULT_MAX_SHOTS = 6

# NOTE: Playwright is imported lazily inside _capture_async, not at module top.
# This module is pulled in by collection_runner (hence most of the app), and
# eagerly importing Playwright's heavy browser driver everywhere is needless
# overhead — it is only needed when a screenshot is actually taken.

_UNAVAILABLE_MSG = (
    'playwright not installed. '
    'Run: pip install playwright && python -m playwright install chromium'
)


def classify_url(url: str) -> Optional[str]:
    """Map a URL to a page-type label (login/admin/…), or ``None``.

    Pure and deterministic (invariant I5): selection logic is testable without
    a browser. Assets (css/img/js) never match a page-type signature, so they
    fall out naturally — only interesting pages get labelled.
    """
    parts = urlparse(url)
    haystack = (parts.path + ('?' + parts.query if parts.query else '')).lower()
    for label, needles in PAGE_TYPES:
        if any(n in haystack for n in needles):
            return label
    return None


def select_targets(report: Dict, base_url: Optional[str] = None,
                   max_shots: int = DEFAULT_MAX_SHOTS,
                   probe_common: bool = True) -> List[Dict]:
    """Pick the pages to screenshot from a collection ``report``.

    Homepage first, then pages the crawl already saw classified by type
    (login/admin/…), then a bounded set of common sensitive paths to probe.
    Deduplicated by label and by URL, capped at ``max_shots``, deterministic —
    a pure function over the report (no network), so it is unit-testable (I5).
    """
    home = base_url or report.get('url')
    targets: List[Dict] = []
    seen_urls = set()
    seen_labels = set()

    def add(label, url, probed=False):
        if not url or url in seen_urls or label in seen_labels:
            return
        targets.append({'label': label, 'url': url, 'probed': probed})
        seen_urls.add(url)
        seen_labels.add(label)

    if home:
        add('home', home)

    # Pages the crawl actually visited, classified by URL keyword.
    capture = report.get('phases', {}).get('capture', {})
    site_map = capture.get('data', {}).get('site_map', []) if isinstance(
        capture, dict) else []
    for entry in sorted(site_map, key=lambda e: str(e.get('url', ''))):
        if not isinstance(entry, dict):
            continue
        url = entry.get('url')
        label = classify_url(url) if url else None
        if label:
            add(label, url)

    # Probe well-known paths even if never linked (still bounded by max_shots).
    if probe_common and home:
        for label, path in COMMON_PATHS:
            add(label, urljoin(home, path), probed=True)

    return targets[:max_shots]


class ScreenshotCapturer:
    """Save a headless-browser screenshot of a page to disk."""

    def __init__(self, timeout_ms: int = 15000, full_page: bool = True):
        self.timeout_ms = timeout_ms
        self.full_page = full_page
        self.progress_callback: Optional[Callable] = None

    @staticmethod
    def available() -> bool:
        # Reuse the central detector (find_spec — no heavy import). Single
        # source of truth for "is Playwright present?" (invariant I3).
        return has_playwright()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    # ----------------------------------------------------------- playwright
    async def _capture_async(self, url: str, out_path: Path) -> Optional[int]:
        from playwright.async_api import async_playwright  # lazy (see note above)
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                resp = await page.goto(url, timeout=self.timeout_ms,
                                       wait_until='load')
                await page.screenshot(path=str(out_path),
                                      full_page=self.full_page)
                return resp.status if resp else None
            finally:
                await browser.close()

    def _run_in_thread(self, url: str, out_path: Path) -> Optional[int]:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._capture_async(url, out_path))
        finally:
            loop.close()

    # ----------------------------------------------------------------- api
    def capture(self, url: str, out_path: Union[str, Path]) -> Dict:
        """Screenshot ``url`` → PNG at ``out_path``.

        Returns ``{status, url, path, http_status?, error?}``. ``status`` is
        ``Unavailable`` when Playwright is absent, ``Error`` on failure/timeout,
        ``Success`` otherwise.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {'status': 'Error', 'url': url, 'path': None}
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = _UNAVAILABLE_MSG
            return result

        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        timeout_s = self.timeout_ms / 1000 + 20

        self._log(f'[Screenshot] {url}')
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self._run_in_thread, url, out_path)
                http_status = future.result(timeout=timeout_s)
            result['status'] = 'Success'
            result['path'] = str(out_path)
            result['http_status'] = http_status
            self._log(f'[Screenshot] saved {out_path}')
        except concurrent.futures.TimeoutError:
            result['error'] = 'screenshot timed out'
            self._log('[Screenshot] timed out')
        except Exception as e:  # noqa: BLE001 — a browser failure is not fatal
            result['error'] = str(e)
            self._log(f'[Screenshot] failed: {e}')
        return result

    def capture_many(self, targets: List[Dict],
                     out_dir: Union[str, Path]) -> List[Dict]:
        """Screenshot each ``{label, url}`` target into ``out_dir/<label>.png``.

        Returns one row per target ``{label, url, status, http_status?, path?,
        rel_path?, error?, probed}``. Reuses ``capture`` (single source of the
        browser path); a per-target failure is recorded, not raised, so one bad
        page never sinks the run. ``rel_path`` (forward slashes) is set only for
        successful shots, for offline-safe ``<img>`` links in the report (I2).
        """
        out_dir = Path(out_dir)
        results: List[Dict] = []
        if not self.available():
            return results
        for t in targets:
            label = t['label']
            out_path = out_dir / f'{label}.png'
            shot = self.capture(t['url'], out_path)
            row = {
                'label': label, 'url': shot.get('url', t['url']),
                'status': shot['status'], 'http_status': shot.get('http_status'),
                'path': shot.get('path'), 'error': shot.get('error'),
                'probed': t.get('probed', False),
            }
            if shot['status'] == 'Success':
                row['rel_path'] = f'screenshots/{label}.png'
            results.append(row)
        return results
