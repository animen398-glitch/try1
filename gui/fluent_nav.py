"""gui/fluent_nav.py — FluentWindow shell wiring for variant B (P3b).

The app's main window is a qfluentwidgets ``FluentWindow`` (frameless, Fluent side
navigation built in). FluentWindow is *not* a QMainWindow — it has no ``menuBar``
and no ``QStatusBar`` — so this module supplies the three pieces the existing
mixin-based window expects, without changing call sites:

  * ``FluentWindowBase`` — the base class MainWindow subclasses.
  * ``FluentWindowTabs`` — a ``QTabWidget``-compatible facade over FluentWindow's
    own ``stackedWidget`` + ``navigationInterface`` (the small subset the app uses:
    ``addTab`` [plugin contract], ``widget`` [lazy-load], ``count``/``tabText``/
    ``widget`` [tests], ``currentChanged`` signal [lazy-load hook], plus
    ``currentIndex``/``setCurrentIndex``/``currentWidget``/``indexOf``).
  * ``StatusBar`` — a thin bottom bar matching the ``QStatusBar`` API the app uses
    (``showMessage``/``addPermanentWidget``), plus ``install_status_bar`` to mount
    it below FluentWindow's nav+content row.

Variant B is committed to PySide6 (the PyQt5/QTabWidget fallback was dropped in
P3b), so qfluentwidgets is a hard dependency here.
"""

from qtpy.QtCore import QObject, Qt, QTimer, Signal
from qtpy.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from gui._fluent import FluentIcon, FluentWindow

FluentWindowBase = FluentWindow

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


class FluentWindowTabs(QObject):
    """QTabWidget-compatible facade over a FluentWindow's nav + stacked content.

    Lets the plugin contract (``PluginManager.build_into`` → ``addTab``), the
    lazy-load hook (``currentChanged`` + ``widget``) and the GUI tests
    (``count``/``tabText``/``widget``) keep working against ``window.tabs``."""

    currentChanged = Signal(int)

    def __init__(self, window: FluentWindow):
        super().__init__(window)
        self._win = window
        self._stack = window.stackedWidget
        self._titles: list = []
        self._stack.currentChanged.connect(self.currentChanged)

    def addTab(self, widget: QWidget, title: str) -> int:
        index = self._stack.count()
        # FluentWindow keys interfaces by objectName — must be unique & set.
        widget.setObjectName(f"tab{index}")
        self._win.addSubInterface(widget, _icon_for(title), title)
        self._titles.append(title)
        return index

    def count(self) -> int:
        return self._stack.count()

    def widget(self, index: int) -> QWidget:
        return self._stack.widget(index)

    def tabText(self, index: int) -> str:
        return self._titles[index] if 0 <= index < len(self._titles) else ''

    def currentIndex(self) -> int:
        return self._stack.currentIndex()

    def currentWidget(self) -> QWidget:
        return self._stack.currentWidget()

    def indexOf(self, widget: QWidget) -> int:
        return self._stack.indexOf(widget)

    def setCurrentIndex(self, index: int) -> None:
        w = self._stack.widget(index)
        if w is not None:
            self._win.switchTo(w)

    def setCurrentWidget(self, widget: QWidget) -> None:
        self._win.switchTo(widget)


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


def install_status_bar(window: FluentWindow, status_bar: StatusBar) -> None:
    """Mount ``status_bar`` as a full-width bottom row of a FluentWindow.

    FluentWindow lays its nav + content in ``window.hBoxLayout`` set directly on
    the window. We move that row onto an inner widget and give the window a new
    vertical layout: [nav|content] on top, the status bar beneath."""
    row = window.hBoxLayout
    inner = QWidget(window)
    inner.setLayout(row)                     # detaches the row from the window
    outer = QVBoxLayout(window)               # new top-level layout
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(0)
    outer.addWidget(inner, 1)
    status_bar.setMaximumHeight(28)
    outer.addWidget(status_bar, 0, Qt.AlignBottom)
