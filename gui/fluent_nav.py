"""gui/fluent_nav.py — stable left-nav shell for the mixin-based GUI.

The first PySide6/Fluent shell used qfluentwidgets ``FluentWindow``. It looked
nice, but in the frozen Windows app the frameless title bar and navigation wheel
events were brittle. This module keeps the public facade the rest of the app
uses, but backs it with a native ``QMainWindow`` + ``QStackedWidget`` + a custom
scrollable left rail. Native window chrome means minimize/maximize/close, drag
and resize are handled by Windows itself.

  * ``FluentWindowBase`` — the base class MainWindow subclasses.
  * ``FluentWindowTabs`` — a ``QTabWidget``-compatible facade over the shell's
    ``stackedWidget`` + ``navigationInterface`` (the small subset the app uses:
    ``addTab`` [plugin contract], ``widget`` [lazy-load], ``count``/``tabText``/
    ``widget`` [tests], ``currentChanged`` signal [lazy-load hook], plus
    ``currentIndex``/``setCurrentIndex``/``currentWidget``/``indexOf``).
  * ``StatusBar`` — a thin bottom bar matching the ``QStatusBar`` subset the app
    uses (``showMessage``/``addPermanentWidget``).
"""

from dataclasses import dataclass

from qtpy.QtCore import QObject, Qt, QTimer, Signal
from qtpy.QtCore import QSize
from qtpy.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton, QScrollArea,
    QSizePolicy, QStackedWidget, QVBoxLayout, QWidget,
)

from gui._fluent import FluentIcon, NavigationItemPosition

_NAV_WIDTH = 280
_NAV_COLLAPSED_WIDTH = 56


@dataclass
class _NavigationItem:
    routeKey: str
    widget: QPushButton
    text: str
    selectable: bool = True


class StableNavigationInterface(QFrame):
    """Left navigation rail with a wheel-scrollable middle section."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.panel = self
        self.items: dict[str, _NavigationItem] = {}
        self._current_route = ""
        self._expanded = True

        self.setObjectName("stableNavigation")
        self.setFixedWidth(_NAV_WIDTH)
        self.setFrameShape(QFrame.NoFrame)

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 8, 4, 8)
        root.setSpacing(4)

        self.topLayout = QVBoxLayout()
        self.topLayout.setContentsMargins(0, 0, 0, 0)
        self.topLayout.setSpacing(4)
        root.addLayout(self.topLayout, 0)
        self.menuButton = QPushButton("☰", self)
        self.menuButton.setProperty("navItem", True)
        self.menuButton.setCursor(Qt.PointingHandCursor)
        self.menuButton.setMinimumHeight(44)
        self.menuButton.setToolTip("Свернуть/развернуть меню")
        self.menuButton.clicked.connect(self.toggle)
        self.topLayout.addWidget(self.menuButton)

        self.scrollArea = QScrollArea(self)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setFrameShape(QFrame.NoFrame)
        self.scrollArea.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scrollArea.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scrollWidget = QWidget()
        self.scrollLayout = QVBoxLayout(self.scrollWidget)
        self.scrollLayout.setContentsMargins(0, 0, 0, 0)
        self.scrollLayout.setSpacing(4)
        self.scrollLayout.addStretch(1)
        self.scrollArea.setWidget(self.scrollWidget)
        root.addWidget(self.scrollArea, 1)

        self.bottomLayout = QVBoxLayout()
        self.bottomLayout.setContentsMargins(0, 0, 0, 0)
        self.bottomLayout.setSpacing(4)
        root.addLayout(self.bottomLayout, 0)

        # Rail palette lives in gui.theme (single source) so the sidebar tracks
        # the active theme instead of hardcoding greys. The theme is applied on
        # the QApplication before MainWindow is built, so is_dark() is correct here.
        from gui import theme
        self.setStyleSheet(theme.navigation_qss())

    def addItem(self, routeKey: str, icon, text: str, onClick=None,
                selectable=True, position=NavigationItemPosition.TOP,
                tooltip: str = None, parentRouteKey: str = None):
        return self.insertItem(-1, routeKey, icon, text, onClick, selectable,
                               position, tooltip, parentRouteKey)

    def insertItem(self, index: int, routeKey: str, icon, text: str,
                   onClick=None, selectable=True,
                   position=NavigationItemPosition.TOP, tooltip: str = None,
                   parentRouteKey: str = None):
        if routeKey in self.items:
            return self.items[routeKey].widget

        display_text = text.replace("&", "&&")
        button = QPushButton(display_text, self)
        button.setProperty("navItem", True)
        button.setCheckable(bool(selectable))
        button.setCursor(Qt.PointingHandCursor)
        button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        button.setMinimumHeight(44)
        button.setToolTip(tooltip or text)
        button.setIconSize(QSize(22, 22))
        qicon = _qicon(icon)
        if not qicon.isNull():
            try:
                button.setIcon(qicon)
            except TypeError:
                # If this module is imported outside main.py before QT_API is
                # pinned, qfluentwidgets can hand us a QIcon from a different
                # Qt binding. Text navigation is still fully usable.
                pass

        if onClick is not None:
            button.clicked.connect(lambda *_: onClick())
        if selectable:
            button.clicked.connect(lambda _checked=False, _rk=routeKey: self.setCurrentItem(_rk))

        self.items[routeKey] = _NavigationItem(routeKey, button, display_text,
                                               selectable)
        layout = self._layout_for(position)
        if layout is self.scrollLayout:
            insert_at = max(0, layout.count() - 1) if index < 0 else index
            layout.insertWidget(insert_at, button)
        else:
            layout.insertWidget(index if index >= 0 else layout.count(), button)
        return button

    def addSeparator(self, position=NavigationItemPosition.TOP):
        separator = QFrame(self)
        separator.setFrameShape(QFrame.HLine)
        # Coloured by the rail stylesheet (gui.theme.navigation_qss), theme-aware.
        separator.setProperty("navSep", True)
        self._layout_for(position).insertWidget(
            max(0, self.scrollLayout.count() - 1)
            if position == NavigationItemPosition.SCROLL else -1,
            separator,
        )

    def addWidget(self, routeKey: str, widget: QWidget, onClick=None,
                  position=NavigationItemPosition.TOP, tooltip: str = None,
                  parentRouteKey: str = None):
        self.insertWidget(-1, routeKey, widget, onClick, position, tooltip,
                          parentRouteKey)

    def insertWidget(self, index: int, routeKey: str, widget: QWidget,
                     onClick=None, position=NavigationItemPosition.TOP,
                     tooltip: str = None, parentRouteKey: str = None):
        if routeKey in self.items:
            return
        if tooltip:
            widget.setToolTip(tooltip)
        self.items[routeKey] = _NavigationItem(routeKey, widget, "", False)
        self._layout_for(position).insertWidget(index, widget)

    def widget(self, routeKey: str):
        return self.items[routeKey].widget

    def setCurrentItem(self, routeKey: str):
        if routeKey not in self.items:
            return
        self._current_route = routeKey
        for key, item in self.items.items():
            if hasattr(item.widget, "setChecked"):
                item.widget.setChecked(item.selectable and key == routeKey)

    def removeWidget(self, routeKey: str):
        item = self.items.pop(routeKey, None)
        if item is not None:
            item.widget.setParent(None)
            item.widget.deleteLater()

    def setMinimumHeight(self, height: int):
        # Compatibility with qfluent NavigationInterface; QMainWindow layout owns
        # the real sizing.
        return super().setMinimumHeight(0)

    def layoutMinHeight(self):
        return self.minimumSizeHint().height()

    def toggle(self):
        self.setExpanded(not self._expanded)

    def setExpanded(self, expanded: bool):
        self._expanded = bool(expanded)
        self.setFixedWidth(_NAV_WIDTH if self._expanded else _NAV_COLLAPSED_WIDTH)
        self.menuButton.setText("☰" if self._expanded else "☰")
        for item in self.items.values():
            if not isinstance(item.widget, QPushButton):
                continue
            item.widget.setText(item.text if self._expanded else "")
            item.widget.setToolTip(item.text.replace("&&", "&"))

    def _layout_for(self, position):
        if position == NavigationItemPosition.BOTTOM:
            return self.bottomLayout
        if position == NavigationItemPosition.TOP:
            return self.topLayout
        return self.scrollLayout


class StableWindowBase(QMainWindow):
    """Native-window shell with a left nav and stacked page area."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.navigationInterface = StableNavigationInterface(self)
        self.stackedWidget = QStackedWidget(self)

        root = QWidget(self)
        self._outer_layout = QVBoxLayout(root)
        self._outer_layout.setContentsMargins(0, 0, 0, 0)
        self._outer_layout.setSpacing(0)
        self.hBoxLayout = QHBoxLayout()
        self.hBoxLayout.setContentsMargins(0, 0, 0, 0)
        self.hBoxLayout.setSpacing(0)
        self.hBoxLayout.addWidget(self.navigationInterface, 0)
        self.hBoxLayout.addWidget(self.stackedWidget, 1)
        self._outer_layout.addLayout(self.hBoxLayout, 1)
        self.setCentralWidget(root)

    def addSubInterface(self, interface: QWidget, icon, text: str,
                        position=NavigationItemPosition.TOP, parent=None,
                        isTransparent=False):
        if not interface.objectName():
            raise ValueError("The object name of `interface` can't be empty string.")
        self.stackedWidget.addWidget(interface)
        route_key = interface.objectName()
        item = self.navigationInterface.addItem(
            routeKey=route_key,
            icon=icon,
            text=text,
            onClick=lambda *_: self.switchTo(interface),
            position=position,
            tooltip=text,
        )
        if self.stackedWidget.count() == 1:
            self.switchTo(interface)
        return item

    def switchTo(self, interface: QWidget):
        self.stackedWidget.setCurrentWidget(interface)
        self.navigationInterface.setCurrentItem(interface.objectName())


FluentWindowBase = StableWindowBase

# Tab title → Fluent icon name (resolved with a safe fallback so an unknown name
# never crashes). Keeps the nav readable without touching the plugin contract.
_TAB_ICONS = {
    "Recon & Intel": "SEARCH",
    "Subdomain Scanner": "GLOBE",
    "API Key Scanner": "VPN",
    "Site Capture": "DOWNLOAD",
    "Clone Frontend": "COPY",
    "Video Downloader": "VIDEO",
    "Image Extractor": "PHOTO",
    "Design Lab": "PALETTE",
    "Cookie Security Audit": "CAFE",
    "Security Audit": "CERTIFICATE",
    "Final Report & Collection": "DOCUMENT",
    "Findings": "FLAG",
    "Assets": "TILES",
    "Timeline": "HISTORY",
    "Overview": "VIEW",
    "Dashboard": "SPEED_HIGH",
    "История операций": "HISTORY",
    "System": "DEVELOPER_TOOLS",
}


def _icon_for(title: str):
    """A FluentIcon for a tab title, falling back to a generic tag icon."""
    return getattr(FluentIcon, _TAB_ICONS.get(title, ""), FluentIcon.TAG)


def _qicon(icon):
    if hasattr(icon, "icon"):
        return icon.icon()
    return icon


class FluentWindowTabs(QObject):
    """QTabWidget-compatible facade over a FluentWindow's nav + stacked content.

    Lets the plugin contract (``PluginManager.build_into`` → ``addTab``), the
    lazy-load hook (``currentChanged`` + ``widget``) and the GUI tests
    (``count``/``tabText``/``widget``) keep working against ``window.tabs``."""

    currentChanged = Signal(int)

    def __init__(self, window: StableWindowBase):
        super().__init__(window)
        self._win = window
        self._stack = window.stackedWidget
        self._titles: list = []
        self._widgets: list = []
        self._containers: dict = {}
        self._stack.currentChanged.connect(self.currentChanged)

    def addTab(self, widget: QWidget, title: str, position: str = 'top',
               new_section: bool = False) -> int:
        """Add a tab to the nav + content stack (plugin contract).

        ``position='bottom'`` anchors a utility tab to the bottom of the nav rail;
        ``new_section`` draws a separator above a top tab that starts a new IA
        cluster. Both are best-effort over the live Fluent nav — a failure to draw
        a separator never blocks the tab from being added."""
        index = self._stack.count()
        container = self._scroll_container(widget)
        # FluentWindow keys interfaces by objectName — must be unique & set.
        container.setObjectName(f"tab{index}")
        pos = (NavigationItemPosition.BOTTOM if position == 'bottom'
               else NavigationItemPosition.SCROLL)
        if new_section and pos == NavigationItemPosition.SCROLL:
            try:
                self._win.navigationInterface.addSeparator(pos)
            except Exception:   # noqa: BLE001 — a separator is cosmetic
                pass
        self._win.addSubInterface(container, _icon_for(title), title,
                                  position=pos)
        self._titles.append(title)
        self._widgets.append(widget)
        self._containers[widget] = container
        return index

    @staticmethod
    def _scroll_container(widget: QWidget) -> QScrollArea:
        """Wrap a tab in a vertical scroll area without changing its API.

        Many legacy tab builders assume a large desktop height. The Fluent
        shell is denser, so a single wrapper gives every tab a right-side
        scrollbar while ``widget(index)`` still returns the original tab.
        """
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(widget)
        return scroll

    def count(self) -> int:
        return self._stack.count()

    def widget(self, index: int) -> QWidget:
        return self._widgets[index]

    def tabText(self, index: int) -> str:
        return self._titles[index] if 0 <= index < len(self._titles) else ''

    def currentIndex(self) -> int:
        return self._stack.currentIndex()

    def currentWidget(self) -> QWidget:
        current = self._stack.currentWidget()
        if isinstance(current, QScrollArea):
            inner = current.widget()
            if inner is not None:
                return inner
        return current

    def indexOf(self, widget: QWidget) -> int:
        if widget in self._widgets:
            return self._widgets.index(widget)
        return self._stack.indexOf(widget)

    def setCurrentIndex(self, index: int) -> None:
        w = self._stack.widget(index)
        if w is not None:
            self._win.switchTo(w)

    def setCurrentWidget(self, widget: QWidget) -> None:
        self._win.switchTo(self._containers.get(widget, widget))


class StatusBar(QWidget):
    """A minimal bottom status bar with the ``QStatusBar`` subset the app uses:
    ``showMessage(text, timeout=0)`` and ``addPermanentWidget(widget)``."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 4, 12, 4)
        self._layout.setSpacing(8)
        self._message = QLabel("")
        self._layout.addWidget(self._message)
        self._layout.addStretch(1)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(lambda: self._message.setText(""))

    def showMessage(self, text: str, timeout: int = 0) -> None:
        self._message.setText(text)
        self._timer.stop()
        if timeout > 0:
            self._timer.start(timeout)

    def currentMessage(self) -> str:
        return self._message.text()

    def addPermanentWidget(self, widget: QWidget) -> None:
        # Permanent widgets sit to the right of the stretch (like QStatusBar).
        self._layout.addWidget(widget)


def install_status_bar(window: StableWindowBase, status_bar: StatusBar) -> None:
    """Mount ``status_bar`` as a full-width bottom row."""
    status_bar.setMaximumHeight(28)
    window._outer_layout.addWidget(status_bar, 0, Qt.AlignBottom)
