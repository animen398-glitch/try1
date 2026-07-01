"""Per-tab upfront degradation when an optional feature is missing.

The GUI must signal a missing optional dependency before the user runs a
doomed task (consistent with the Scrapy plugin's disabled+hint pattern),
not only fail afterwards:
  * Recon tab — "Dynamic API Sniffing" needs Playwright.
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
