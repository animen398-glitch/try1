from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QGroupBox, QPushButton, QTextEdit


class StyledButton(QPushButton):
    """Кастомная кнопка с предустановленными стилями"""

    STYLES = {
        'primary': """
            QPushButton {
                background-color: #0078d4; color: white;
                border: none; border-radius: 4px;
                padding: 8px 16px; font-size: 13px; font-weight: 500;
            }
            QPushButton:hover { background-color: #006bc1; }
            QPushButton:pressed { background-color: #005ea2; }
            QPushButton:disabled { background-color: #cccccc; color: #666666; }
        """,
        'danger': """
            QPushButton {
                background-color: #d32f2f; color: white;
                border: none; border-radius: 4px;
                padding: 8px 16px; font-size: 13px;
            }
            QPushButton:hover { background-color: #b71c1c; }
            QPushButton:pressed { background-color: #7f0000; }
        """,
        'success': """
            QPushButton {
                background-color: #2e7d32; color: white;
                border: none; border-radius: 4px;
                padding: 8px 16px; font-size: 13px;
            }
            QPushButton:hover { background-color: #1b5e20; }
        """,
        'secondary': """
            QPushButton {
                background-color: #f5f5f5; color: #333333;
                border: 1px solid #cccccc; border-radius: 4px;
                padding: 8px 16px; font-size: 13px;
            }
            QPushButton:hover { background-color: #e0e0e0; }
        """,
    }

    def __init__(self, text: str, style: str = 'primary', parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(self.STYLES.get(style, self.STYLES['primary']))
        self.setMinimumHeight(34)


class SectionGroupBox(QGroupBox):
    """QGroupBox с единым стилем для всех секций"""

    def __init__(self, title: str, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet("""
            QGroupBox {
                font-weight: bold; font-size: 13px;
                border: 1px solid #cccccc; border-radius: 6px;
                margin-top: 12px; padding-top: 8px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px; padding: 0 5px;
            }
        """)


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

    def append_info(self, text: str):
        self.append(f'<span style="color:#4fc3f7;">[INFO]</span> {text}')

    def append_success(self, text: str):
        self.append(f'<span style="color:#81c784;">[OK]</span> {text}')

    def append_error(self, text: str):
        self.append(f'<span style="color:#e57373;">[ERR]</span> {text}')

    def append_warning(self, text: str):
        self.append(f'<span style="color:#ffb74d;">[WARN]</span> {text}')

    def append_high(self, text: str):
        self.append(f'<span style="color:#ff5252; font-weight:bold;">[HIGH]</span> {text}')

    def append_medium(self, text: str):
        self.append(f'<span style="color:#ffb74d; font-weight:bold;">[MEDIUM]</span> {text}')
