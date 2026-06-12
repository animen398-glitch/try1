"""Screenshot capturer + collection integration — offline (Playwright stubbed).

The real browser path needs Playwright (an optional, unbundled dependency), so
these tests exercise the gating/degradation and the wiring with the browser
call stubbed out — matching how the dynamic/scrapy features are tested.
"""

from core.collection_runner import CollectionRunner
from core.screenshot import ScreenshotCapturer


def _set_available(monkeypatch, value: bool):
    monkeypatch.setattr(ScreenshotCapturer, 'available', staticmethod(lambda: value))


# ── capture(): gating + success path ────────────────────────────────────────

def test_capture_unavailable_when_playwright_missing(tmp_path, monkeypatch):
    _set_available(monkeypatch, False)
    cap = ScreenshotCapturer()
    out = cap.capture('https://ex.com', tmp_path / 's.png')
    assert out['status'] == 'Unavailable'
    assert 'playwright' in out['error'].lower()
    assert out['path'] is None
    # The URL is normalised even on the degraded path.
    assert out['url'] == 'https://ex.com'


def test_capture_prefixes_scheme(tmp_path, monkeypatch):
    _set_available(monkeypatch, False)
    out = ScreenshotCapturer().capture('ex.com', tmp_path / 's.png')
    assert out['url'] == 'https://ex.com'


def test_capture_success_with_stubbed_browser(tmp_path, monkeypatch):
    _set_available(monkeypatch, True)

    def fake_run(self, url, out_path):
        out_path.write_bytes(b'\x89PNG\r\n')   # pretend the browser wrote a PNG
        return 200

    monkeypatch.setattr(ScreenshotCapturer, '_run_in_thread', fake_run)
    out_file = tmp_path / 'shots' / 'home.png'
    out = ScreenshotCapturer().capture('https://ex.com', out_file)
    assert out['status'] == 'Success'
    assert out['http_status'] == 200
    assert out_file.exists()
    assert out['path'] == str(out_file)


def test_capture_handles_browser_error(tmp_path, monkeypatch):
    _set_available(monkeypatch, True)

    def boom(self, url, out_path):
        raise RuntimeError('chromium crashed')

    monkeypatch.setattr(ScreenshotCapturer, '_run_in_thread', boom)
    out = ScreenshotCapturer().capture('https://ex.com', tmp_path / 's.png')
    assert out['status'] == 'Error'
    assert 'chromium crashed' in out['error']


# ── collection phase integration ────────────────────────────────────────────

def test_collection_screenshot_skipped_when_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(ScreenshotCapturer, 'available', staticmethod(lambda: False))
    runner = CollectionRunner(screenshots=True)
    phase = runner._phase_screenshot('https://ex.com', tmp_path)
    assert phase['status'] == 'Skipped'
    assert 'playwright' in phase['reason'].lower()


def test_collection_screenshot_phase_success(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(ScreenshotCapturer, 'available', staticmethod(lambda: True))

    def fake_capture(self, url, out):
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_bytes(b'\x89PNG')
        return {'status': 'Success', 'path': str(out)}

    monkeypatch.setattr(ScreenshotCapturer, 'capture', fake_capture)
    runner = CollectionRunner(screenshots=True)
    phase = runner._phase_screenshot('https://ex.com', tmp_path)
    assert phase['status'] == 'Success'
    # Report links the image by a URL-style relative path (forward slashes →
    # offline-safe and resolves on Windows too).
    assert phase['data']['rel_path'] == 'screenshots/home.png'


def test_default_collection_has_no_screenshot_flag():
    # Screenshots are opt-in; the default pipeline must not enable them.
    assert CollectionRunner().screenshots is False


def test_report_renders_screenshot_card(tmp_path):
    runner = CollectionRunner()
    report = {
        'url': 'https://ex.com', 'domain': 'ex.com',
        'started_at': 't0', 'finished_at': 't1', 'project_dir': str(tmp_path),
        'phases': {
            'screenshot': {'status': 'Success',
                           'data': {'rel_path': 'screenshots/home.png'}},
        },
    }
    html = runner._render_html(report)
    assert 'Screenshot' in html
    # Relative <img> source → offline-safe (no absolute path, no remote URL).
    assert 'src="screenshots/home.png"' in html
    assert 'http://' not in html.split('<img')[1][:80]
