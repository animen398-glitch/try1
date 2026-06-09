import json
from pathlib import Path

from PyQt5.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog,
    QHBoxLayout, QLabel, QLineEdit, QSpinBox,
    QTabWidget, QVBoxLayout, QWidget,
)

from gui.ui_components import SectionGroupBox, StyledButton

SETTINGS_FILE = Path(__file__).parent.parent / 'configs' / 'settings.json'


class SettingsDialog(QDialog):
    """Диалог настроек приложения"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setMinimumSize(500, 380)
        self.settings = self._load_settings()
        self._build_ui()

    def _load_settings(self) -> dict:
        try:
            if SETTINGS_FILE.exists():
                return json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
        except Exception:
            pass
        return {
            'output_dir': str(Path.home() / 'SiteAnalyzer'),
            'max_pages': 50,
            'request_delay': 500,
            'auto_compress': False,
        }

    def _save_settings(self):
        try:
            SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(
                json.dumps(self.settings, indent=2, ensure_ascii=False),
                encoding='utf-8'
            )
        except Exception:
            pass

    def _build_ui(self):
        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        tabs.addTab(self._build_paths_tab(), "Пути")
        tabs.addTab(self._build_network_tab(), "Сеть")
        tabs.addTab(self._build_output_tab(), "Вывод")
        layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_paths_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Директория для сохранения результатов")
        g_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit(self.settings.get('output_dir', ''))
        browse_btn = StyledButton("Обзор...", style='secondary')
        browse_btn.clicked.connect(self._browse_output_dir)
        g_layout.addWidget(self.output_dir_edit)
        g_layout.addWidget(browse_btn)
        group.setLayout(g_layout)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _build_network_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Параметры запросов")
        g_layout = QVBoxLayout()

        g_layout.addWidget(QLabel("Макс. страниц для сканирования:"))
        self.max_pages_spin = QSpinBox()
        self.max_pages_spin.setRange(1, 500)
        self.max_pages_spin.setValue(self.settings.get('max_pages', 50))
        g_layout.addWidget(self.max_pages_spin)

        g_layout.addWidget(QLabel("Задержка между запросами (мс):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10000)
        self.delay_spin.setSingleStep(100)
        self.delay_spin.setValue(self.settings.get('request_delay', 500))
        g_layout.addWidget(self.delay_spin)

        group.setLayout(g_layout)
        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _build_output_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Архивация")
        g_layout = QVBoxLayout()
        self.auto_compress_cb = QCheckBox("Авто-архивация результатов в ZIP")
        self.auto_compress_cb.setChecked(self.settings.get('auto_compress', False))
        g_layout.addWidget(self.auto_compress_cb)
        group.setLayout(g_layout)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _browse_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку", self.output_dir_edit.text())
        if path:
            self.output_dir_edit.setText(path)

    def _on_accept(self):
        self.settings['output_dir'] = self.output_dir_edit.text()
        self.settings['max_pages'] = self.max_pages_spin.value()
        self.settings['request_delay'] = self.delay_spin.value()
        self.settings['auto_compress'] = self.auto_compress_cb.isChecked()
        self._save_settings()
        self.accept()

    def get_settings(self) -> dict:
        return self.settings.copy()
