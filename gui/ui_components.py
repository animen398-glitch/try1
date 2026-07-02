import html
import re

from qtpy.QtCore import QPoint, QRect, QSize, Qt
from qtpy.QtGui import QFont
from qtpy.QtWidgets import (
    QComboBox, QGroupBox, QHBoxLayout, QLabel, QLayout, QPushButton, QTextBrowser,
    QTextEdit, QWidget,
)

from gui import theme

# A finding's location, an export path, an endpoint — these show up all over the
# UI and users expect to click/copy them. ``linkify`` and the helpers below are
# the single place that turns such text into selectable, clickable content so no
# tab re-implements it (Task 4). http(s) URLs are wrapped in anchors; everything
# else is HTML-escaped so it can never inject markup.
_URL_RE = re.compile(r'(https?://[^\s<>"\')]+)')
_TRAILING_URL_PUNCT = '.,;:!'

# Flags that make a QLabel's text selectable by mouse + keyboard and let links be
# clicked — the standard "you can read, select, copy and open this" set.
SELECTABLE_FLAGS = (Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
                    | Qt.LinksAccessibleByMouse)


def linkify(text, *, newlines_to_br: bool = True) -> str:
    """HTML-escape ``text`` and wrap any http(s) URL in a clickable anchor.

    Pure/string-only (unit-tested): the rest of the text is escaped first, so a
    value can never inject markup; newlines become ``<br>`` for rich-text widgets
    unless disabled.
    """
    def _anchor(match):
        url = match.group(1)
        clean = url.rstrip(_TRAILING_URL_PUNCT)
        suffix = url[len(clean):]
        return f'<a href="{clean}">{clean}</a>{suffix}'

    escaped = html.escape(str(text))
    out = _URL_RE.sub(_anchor, escaped)
    if newlines_to_br:
        out = out.replace('\n', '<br>')
    return out


def make_selectable_label(text: str = '', parent=None) -> QLabel:
    """A QLabel whose plain text can be selected and copied (no link parsing)."""
    label = QLabel(str(text), parent)
    label.setTextInteractionFlags(SELECTABLE_FLAGS)
    label.setCursor(Qt.IBeamCursor)
    label.setWordWrap(True)
    return label


def make_link_label(url: str, text: str = None, parent=None) -> QLabel:
    """A QLabel showing ``url`` (or ``text``) as a clickable, selectable link that
    opens in the system browser."""
    safe_url = html.escape(str(url), quote=True)
    caption = html.escape(str(text if text is not None else url))
    label = QLabel(f'<a href="{safe_url}">{caption}</a>', parent)
    label.setTextInteractionFlags(SELECTABLE_FLAGS)
    label.setOpenExternalLinks(True)
    label.setCursor(Qt.IBeamCursor)
    label.setWordWrap(True)
    return label


class SelectableText(QLabel):
    """Selectable/copyable label for short values (paths, endpoints, IDs)."""

    def __init__(self, text: str = '', parent=None):
        super().__init__(str(text), parent)
        self.setTextInteractionFlags(SELECTABLE_FLAGS)
        self.setCursor(Qt.IBeamCursor)
        self.setWordWrap(True)


class LinkTextBrowser(QTextBrowser):
    """Read-only text panel for longer content where URLs must be clickable and
    everything stays selectable/copyable — without breaking plain-text logs
    (those keep using ResultsDisplay). Use ``set_linkified`` to feed plain text.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setOpenExternalLinks(True)
        self.setFont(QFont('Consolas', 10))
        self.setStyleSheet("""
            QTextBrowser {
                background-color: #1e1e1e; color: #d4d4d4;
                border: 1px solid #555; border-radius: 4px; padding: 6px;
            }
        """)

    def set_linkified(self, text: str):
        """Show ``text`` with URLs turned into clickable links (rest escaped)."""
        self.setHtml(linkify(text))


class FlowLayout(QLayout):
    """Layout that lays widgets out left-to-right and **wraps to a new row** when
    the available width runs out, reflowing to as many rows as needed.

    Used for long option rows (e.g. the Collection tab's opt-in checkboxes) so
    they never clip off the right edge on a narrow window — on a wide one they
    stay on a single row, on a narrow one they break onto two+. Adapted from Qt's
    canonical FlowLayout example; binding-agnostic via qtpy (no ``addStretch`` —
    wrapping replaces it)."""

    def __init__(self, parent=None, margin=0, spacing=8):
        super().__init__(parent)
        if parent is not None:
            self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self._items = []

    def __del__(self):
        while self.count():
            self.takeAt(0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QSize(margins.left() + margins.right(),
                      margins.top() + margins.bottom())
        return size

    def _do_layout(self, rect, test_only):
        left, top, right, bottom = self.getContentsMargins()
        effective = rect.adjusted(left, top, -right, -bottom)
        x, y, line_height = effective.x(), effective.y(), 0
        spacing = self.spacing()
        for item in self._items:
            hint = item.sizeHint()
            next_x = x + hint.width() + spacing
            if next_x - spacing > effective.right() and line_height > 0:
                x = effective.x()
                y = y + line_height + spacing
                next_x = x + hint.width() + spacing
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x = next_x
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + bottom


class StyledButton(QPushButton):
    """Кнопка с предустановленным стилем.

    Цвета берутся из ``gui.theme`` (единый источник chrome-палитры, F6 T6.3) и
    подбираются под активную тему на момент создания виджета. Публичный контракт
    ``StyledButton(text, style=...)`` не изменился; цветные стили (primary/danger/
    success) одинаковы в светлой и тёмной теме, нейтральный ``secondary`` —
    адаптируется."""

    def __init__(self, text: str, style: str = 'primary', parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(theme.button_qss(style))
        self.setMinimumHeight(34)


class SectionGroupBox(QGroupBox):
    """QGroupBox с единым стилем секций (граница из ``gui.theme``, F6 T6.3)."""

    def __init__(self, title: str, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet(theme.group_box_qss())


class ResultsDisplay(QTextEdit):
    """Цветная область вывода результатов (только для чтения)"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont('Consolas', 10))
        self.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e; color: #d4d4d4;
                border: 1px solid #555; border-radius: 4px; padding: 6px;
            }
        """)

    # ``append()`` renders its argument as rich text (HTML), so the caller's
    # message — usually a URL, filename, header value or error string — must be
    # escaped; only the coloured ``[LEVEL]`` prefix is intentional markup.
    # Callers that want to emit real HTML use ``append()`` directly.

    def append_info(self, text: str):
        self.append(f'<span style="color:#4fc3f7;">[INFO]</span> {html.escape(str(text))}')

    def append_success(self, text: str):
        self.append(f'<span style="color:#81c784;">[OK]</span> {html.escape(str(text))}')

    def append_error(self, text: str):
        self.append(f'<span style="color:#e57373;">[ERR]</span> {html.escape(str(text))}')

    def append_warning(self, text: str):
        self.append(f'<span style="color:#ffb74d;">[WARN]</span> {html.escape(str(text))}')

    def append_high(self, text: str):
        self.append(f'<span style="color:#ff5252; font-weight:bold;">[HIGH]</span> {html.escape(str(text))}')

    def append_medium(self, text: str):
        self.append(f'<span style="color:#ffb74d; font-weight:bold;">[MEDIUM]</span> {html.escape(str(text))}')


class TablePaginator:
    """Render a large row list into a ``QTableWidget`` one page at a time.

    The slow part of a big table is *populating the widget* (thousands of
    ``QTableWidgetItem``), not holding the rows in memory — so the full,
    already-queried/filtered/sorted list is kept and only a window of it is
    rendered. Adopting tabs pass their table + a per-row render callback
    (``render_row(table, table_row, record)``); selection handlers map a table
    row back to the full-list record via :meth:`record_at`. Pure UI — no data
    layer change. ``widget`` is a control strip (First/◀/▶/Last + a status label
    + a page-size combo) for the tab to place under the table.
    """

    PAGE_SIZES = (100, 200, 500, 1000)

    def __init__(self, table, render_row, *, page_size: int = 200,
                 on_page_changed=None):
        self.table = table
        self._render_row = render_row
        self._on_page_changed = on_page_changed
        self._rows: list = []
        self._page = 0
        self._page_size = int(page_size)
        self.widget = self._build_controls()
        self._refresh_controls()

    def _build_controls(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        self.btn_first = QPushButton('⏮')
        self.btn_prev = QPushButton('◀')
        self.btn_next = QPushButton('▶')
        self.btn_last = QPushButton('⏭')
        for b in (self.btn_first, self.btn_prev, self.btn_next, self.btn_last):
            b.setMaximumWidth(40)
        self.btn_first.clicked.connect(lambda: self.go_to(0))
        self.btn_prev.clicked.connect(lambda: self.go_to(self._page - 1))
        self.btn_next.clicked.connect(lambda: self.go_to(self._page + 1))
        self.btn_last.clicked.connect(lambda: self.go_to(self.page_count() - 1))
        self.page_label = QLabel('Нет строк')
        self.size_combo = QComboBox()
        for n in self.PAGE_SIZES:
            self.size_combo.addItem(f'{n}/стр', n)
        idx = self.size_combo.findData(self._page_size)
        self.size_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.size_combo.currentIndexChanged.connect(self._on_size_changed)
        lay.addWidget(self.btn_first)
        lay.addWidget(self.btn_prev)
        lay.addWidget(self.page_label, stretch=1)
        lay.addWidget(self.btn_next)
        lay.addWidget(self.btn_last)
        lay.addWidget(self.size_combo)
        return w

    # ── data ────────────────────────────────────────────────────────────────
    def set_rows(self, rows) -> None:
        """Replace the full row list and render the first page."""
        self._rows = list(rows or [])
        self._page = 0
        self._render()

    def all_rows(self) -> list:
        return self._rows

    def page_count(self) -> int:
        if not self._rows:
            return 1
        return (len(self._rows) + self._page_size - 1) // self._page_size

    def page_start(self) -> int:
        return self._page * self._page_size

    def index_at(self, table_row) -> int:
        """Full-list index for a table row (page offset + row), or -1."""
        if table_row is None or table_row < 0:
            return -1
        return self.page_start() + int(table_row)

    def record_at(self, table_row):
        idx = self.index_at(table_row)
        return self._rows[idx] if 0 <= idx < len(self._rows) else None

    def reveal(self, index: int) -> int:
        """Navigate to the page holding full-list ``index`` and return its row on
        that page (or -1 if out of range) — so a caller can re-select a record
        that may live on a different page after a reload."""
        if not (0 <= index < len(self._rows)):
            return -1
        self.go_to(index // self._page_size)
        return index - self.page_start()

    def go_to(self, page: int) -> None:
        page = max(0, min(int(page), self.page_count() - 1))
        if page != self._page:
            self._page = page
            self._render()
            if self._on_page_changed:
                self._on_page_changed()

    def _on_size_changed(self) -> None:
        new = self.size_combo.currentData() or self._page_size
        first = self.page_start()                 # keep the first visible row visible
        self._page_size = int(new)
        self._page = first // self._page_size
        self._render()
        if self._on_page_changed:
            self._on_page_changed()

    def _render(self) -> None:
        start = self.page_start()
        window = self._rows[start:start + self._page_size]
        self.table.setRowCount(0)
        for rec in window:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self._render_row(self.table, r, rec)
        self._refresh_controls()

    def _refresh_controls(self) -> None:
        n = len(self._rows)
        pages = self.page_count()
        if n == 0:
            self.page_label.setText('Нет строк')
        else:
            a = self.page_start() + 1
            b = min(self.page_start() + self._page_size, n)
            self.page_label.setText(
                f'стр. {self._page + 1}/{pages} · показано {a}–{b} из {n}')
        self.btn_first.setEnabled(self._page > 0)
        self.btn_prev.setEnabled(self._page > 0)
        self.btn_next.setEnabled(self._page < pages - 1)
        self.btn_last.setEnabled(self._page < pages - 1)
