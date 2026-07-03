"""tests/test_scrapy_cancel_gui.py

The Deep-Crawl (Scrapy) tab's Cancel button, driven through a synchronous test
runner: the tab must hand a cancellation token to the crawl engine, the Cancel
button must set that token, and a cancelled result must surface a clean message
(never a traceback). Headless/offscreen; no real Scrapy or process is spawned.
"""

import pytest

import plugins.scrapy_tab as scrapy_tab
from plugins.scrapy_tab import _ScrapyTab
from utils.subprocess_utils import CancellationToken


class _FakeWindow:
    """Minimal host exposing the shared helpers the tab reaches through."""

    def __init__(self):
        self.settings = {}
        self.saved = []

    def _set_busy(self, busy):
        self.busy = busy

    def _run_async(self, work, on_done=None):
        # Synchronous: run inline so the click → handler → callback chain is
        # deterministic (mirrors TaskRunnerMixin._run_async contract).
        result = work()
        if on_done is not None:
            on_done(result)

    def _save_target(self, url):
        self.saved.append(url)


class _FakeCrawler:
    """Stand-in for ScrapyCrawler that records the token and returns a
    cancelled result (as the real engine does when the token is set)."""

    last = None

    def __init__(self, **kw):
        self.token = None
        _FakeCrawler.last = self

    @staticmethod
    def is_available():
        return True

    def set_cancel_event(self, ev):
        self.token = ev

    def crawl(self, url):
        # Simulate the operator having cancelled: the engine returns the
        # cancelled shape produced by run_capture → scrapy_crawler.crawl.
        return {'status': 'Error', 'url': url, 'items': [], 'pages': 0,
                'error': 'crawl cancelled'}


@pytest.fixture
def tab(qapp, monkeypatch):
    monkeypatch.setattr(scrapy_tab, 'ScrapyCrawler', _FakeCrawler)
    return _ScrapyTab(_FakeWindow())


def test_run_wires_cancel_token_and_handles_cancelled(tab):
    tab.url.setText('https://example.com')
    tab._run()
    # The engine received a real cancellation token.
    assert isinstance(_FakeCrawler.last.token, CancellationToken)
    # Cancelled result → clean message, no traceback, buttons reset.
    assert tab.status.text() == 'Операция отменена'
    assert tab.btn.isEnabled() is True
    assert tab.cancel_btn.isEnabled() is False
    assert tab._cancel_token is None


def test_cancel_button_sets_token(tab, qapp):
    # Arm a live token as if a crawl were running.
    tok = CancellationToken()
    tab._cancel_token = tok
    tab.cancel_btn.setEnabled(True)

    tab.cancel_btn.click()

    assert tok.is_set() is True
    assert tab.cancel_btn.isEnabled() is False
    assert tab.status.text() == 'Отмена…'


def test_cancel_is_noop_when_idle(tab):
    tab._cancel_token = None
    tab._cancel()          # must not raise
