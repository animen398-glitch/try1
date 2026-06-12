"""Per-tab upfront degradation when an optional feature is missing.

The GUI must signal a missing optional dependency before the user runs a
doomed task (consistent with the Scrapy plugin's disabled+hint pattern),
not only fail afterwards:
  * Recon tab — "Dynamic API Sniffing" needs Playwright.
  * Video tab — downloads need the yt-dlp binary.
"""


def test_dynamic_checkbox_disabled_without_playwright(qapp, monkeypatch):
    import gui.tab_recon as tab_recon
    monkeypatch.setattr(tab_recon, "has_playwright", lambda: False)

    from gui.main_window import MainWindow
    w = MainWindow()

    assert not w.chk_dynamic.isEnabled()
    assert "не установлен" in w.chk_dynamic.text()


def test_dynamic_checkbox_enabled_with_playwright(qapp, monkeypatch):
    import gui.tab_recon as tab_recon
    monkeypatch.setattr(tab_recon, "has_playwright", lambda: True)

    from gui.main_window import MainWindow
    w = MainWindow()

    assert w.chk_dynamic.isEnabled()
    assert w.chk_dynamic.text() == "Dynamic API Sniffing"


def test_video_run_blocked_without_ytdlp(qapp, monkeypatch):
    from utils.video_processor import VideoDownloader
    monkeypatch.setattr(VideoDownloader, "is_available", staticmethod(lambda: False))

    from gui.main_window import MainWindow
    w = MainWindow()

    started = []
    w._run_async = lambda *a, **k: started.append(a)

    w.video_url.setText("https://youtube.com/watch?v=x")
    w._run_video()

    # No background download was launched, and the user was told why.
    assert started == []
    assert "yt-dlp" in w.video_results.toPlainText()


def test_video_run_proceeds_with_ytdlp(qapp, monkeypatch):
    from utils.video_processor import VideoDownloader
    monkeypatch.setattr(VideoDownloader, "is_available", staticmethod(lambda: True))

    from gui.main_window import MainWindow
    w = MainWindow()

    started = []
    w._run_async = lambda *a, **k: started.append(a)

    w.video_url.setText("https://youtube.com/watch?v=x")
    w._run_video()

    assert len(started) == 1
