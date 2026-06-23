"""Fluent shell regressions."""

from qtpy.QtWidgets import QScrollArea


def test_fluent_tabs_wrap_content_but_keep_original_widget_contract(qapp):
    from gui.main_window import MainWindow

    window = MainWindow()

    first_original = window.tabs.widget(0)
    first_container = window.stackedWidget.widget(0)

    assert isinstance(first_container, QScrollArea)
    assert first_container.widget() is first_original
    assert window.tabs.currentWidget() is first_original
    assert window.tabs.indexOf(first_original) == 0


def test_fluent_window_controls_are_available(qapp):
    from gui.main_window import MainWindow

    window = MainWindow()
    title_bar = window.titleBar

    assert title_bar.minBtn is not None
    assert title_bar.maxBtn is not None
    assert title_bar.closeBtn is not None
    assert callable(window._toggle_maximized)
