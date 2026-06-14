import html

from qtpy.QtCore import QPoint, QRect, QSize, Qt
from qtpy.QtGui import QFont
from qtpy.QtWidgets import QGroupBox, QLayout, QPushButton, QTextEdit

from gui import theme


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
