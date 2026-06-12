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
from typing import Callable, Dict, Optional, Union

from core.features import has_playwright

# NOTE: Playwright is imported lazily inside _capture_async, not at module top.
# This module is pulled in by collection_runner (hence most of the app), and
# eagerly importing Playwright's heavy browser driver everywhere is needless
# overhead — it is only needed when a screenshot is actually taken.

_UNAVAILABLE_MSG = (
    'playwright not installed. '
    'Run: pip install playwright && python -m playwright install chromium'
)


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
