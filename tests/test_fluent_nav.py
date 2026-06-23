"""Fluent shell regressions."""

from qtpy.QtWidgets import QScrollArea
from qtpy.QtCore import QEvent, QPoint, QPointF, Qt


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
    assert title_bar in window._drag_widgets


def test_fluent_tab_items_live_in_scrollable_navigation_area(qapp):
    from gui.main_window import MainWindow

    window = MainWindow()
    panel = window.navigationInterface.panel
    dashboard_item = panel.items["tab0"].widget

    assert dashboard_item.parent() is panel.scrollWidget
    assert panel.scrollArea.widget() is panel.scrollWidget


def test_fluent_navigation_wheel_scrolls_from_item(qapp):
    from gui.main_window import MainWindow

    class WheelEvent:
        def type(self):
            return QEvent.Wheel

        def angleDelta(self):
            return QPoint(0, -120)

    window = MainWindow()
    panel = window.navigationInterface.panel
    bar = panel.scrollArea.verticalScrollBar()
    bar.setRange(0, 100)
    bar.setValue(0)

    handled = window.eventFilter(panel.items["tab0"].widget, WheelEvent())

    assert handled is True
    assert bar.value() == 100


def test_fluent_titlebar_drag_event_is_handled(qapp):
    from gui.main_window import MainWindow

    class PressEvent:
        def type(self):
            return QEvent.MouseButtonPress

        def button(self):
            return Qt.LeftButton

        def globalPosition(self):
            return QPointF(100, 100)

    window = MainWindow()

    handled = window.eventFilter(window.titleBar, PressEvent())

    assert handled is True
    assert window._drag_pos is not None
