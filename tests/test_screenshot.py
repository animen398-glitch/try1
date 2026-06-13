"""Screenshot capturer + collection integration — offline (Playwright stubbed).

The real browser path needs Playwright (an optional, unbundled dependency), so
these tests exercise the gating/degradation and the wiring with the browser
call stubbed out — matching how the dynamic/scrapy features are tested.
"""

from core.collection_runner import CollectionRunner
from core.screenshot import (
    ScreenshotCapturer, classify_url, select_targets,
)


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


# ── multi-page target selection (pure, offline) ─────────────────────────────

def test_classify_url_page_types():
    assert classify_url('https://x.com/login') == 'login'
    assert classify_url('https://x.com/wp-admin/') == 'admin'
    assert classify_url('https://x.com/app/dashboard') == 'dashboard'
    assert classify_url('https://x.com/api/v1/users') == 'api'
    # Assets and plain pages are not page-types → never screenshotted as such.
    assert classify_url('https://x.com/static/app.css') is None
    assert classify_url('https://x.com/about') is None


def _report_with_sitemap(urls, url='https://x.com'):
    return {'url': url, 'phases': {'capture': {'status': 'Success', 'data': {
        'site_map': [{'url': u, 'status': 200} for u in urls]}}}}


def test_select_targets_homepage_first_and_classified_pages():
    report = _report_with_sitemap([
        'https://x.com/login', 'https://x.com/about',
        'https://x.com/css/app.css', 'https://x.com/user/account'])
    targets = select_targets(report, probe_common=False)
    labels = [t['label'] for t in targets]
    assert labels[0] == 'home'
    assert 'login' in labels and 'account' in labels
    # Asset / plain pages are excluded.
    assert all(t['url'] != 'https://x.com/css/app.css' for t in targets)
    assert all(not t['probed'] for t in targets)   # probing disabled here


def test_select_targets_dedups_label_keeping_first():
    report = _report_with_sitemap([
        'https://x.com/login', 'https://x.com/auth/signin'])
    targets = select_targets(report, probe_common=False)
    login = [t for t in targets if t['label'] == 'login']
    assert len(login) == 1                       # one shot per page-type
    assert login[0]['url'] == 'https://x.com/auth/signin'  # sorted-first wins


def test_select_targets_probes_common_paths_when_absent():
    report = _report_with_sitemap([], url='https://x.com')
    targets = select_targets(report, probe_common=True)
    probed = {t['label']: t for t in targets if t['probed']}
    assert probed['login']['url'] == 'https://x.com/login'
    assert probed['admin']['url'] == 'https://x.com/admin'
    assert probed['dashboard']['url'] == 'https://x.com/dashboard'


def test_select_targets_probe_skips_already_seen_label():
    # A crawled /login means we don't also probe the common /login path.
    report = _report_with_sitemap(['https://x.com/login'])
    targets = select_targets(report, probe_common=True)
    login = [t for t in targets if t['label'] == 'login']
    assert len(login) == 1 and login[0]['probed'] is False


def test_select_targets_respects_max_shots():
    report = _report_with_sitemap([
        'https://x.com/login', 'https://x.com/admin', 'https://x.com/dashboard',
        'https://x.com/account', 'https://x.com/register', 'https://x.com/api'])
    targets = select_targets(report, max_shots=3)
    assert len(targets) == 3
    assert targets[0]['label'] == 'home'        # homepage always kept first


def test_select_targets_no_homepage_no_crash():
    targets = select_targets({'phases': {}}, base_url=None)
    assert targets == []


# ── capture_many (browser stubbed) ──────────────────────────────────────────

def test_capture_many_returns_row_per_target(tmp_path, monkeypatch):
    _set_available(monkeypatch, True)

    def fake_capture(self, url, out_path):
        from pathlib import Path as P
        if 'admin' in url:                       # pretend /admin is 403, no img
            return {'status': 'Error', 'url': url, 'path': None,
                    'http_status': 403, 'error': 'forbidden'}
        P(out_path).parent.mkdir(parents=True, exist_ok=True)
        P(out_path).write_bytes(b'\x89PNG')
        return {'status': 'Success', 'url': url, 'path': str(out_path),
                'http_status': 200}

    monkeypatch.setattr(ScreenshotCapturer, 'capture', fake_capture)
    targets = [{'label': 'home', 'url': 'https://x.com', 'probed': False},
               {'label': 'admin', 'url': 'https://x.com/admin', 'probed': True}]
    rows = ScreenshotCapturer().capture_many(targets, tmp_path)

    assert [r['label'] for r in rows] == ['home', 'admin']
    home = rows[0]
    assert home['status'] == 'Success'
    assert home['rel_path'] == 'screenshots/home.png'
    admin = rows[1]
    assert admin['status'] == 'Error' and admin['http_status'] == 403
    assert 'rel_path' not in admin              # no image link for a failed shot
    assert admin['probed'] is True


def test_capture_many_empty_when_unavailable(tmp_path, monkeypatch):
    _set_available(monkeypatch, False)
    rows = ScreenshotCapturer().capture_many(
        [{'label': 'home', 'url': 'https://x.com'}], tmp_path)
    assert rows == []


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
