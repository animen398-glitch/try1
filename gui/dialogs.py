import os

from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QSpinBox,
    QTabWidget, QVBoxLayout, QWidget,
)

from core import config
from gui.ui_components import SectionGroupBox, StyledButton
from utils.browser_utils import BROWSER_HEADERS

# User-Agent profiles the request layer (SessionBuilder) actually supports.
_UA_PROFILES = list(BROWSER_HEADERS.keys())
_ARCHIVE_FORMATS = ['zip', 'rar']


class SettingsDialog(QDialog):
    """Диалог настроек приложения"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setMinimumSize(500, 380)
        self.settings = config.load_settings()
        self._build_ui()

    def _save_settings(self):
        config.save_settings(self.settings)

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

        g_layout.addWidget(QLabel("Профиль User-Agent:"))
        self.ua_combo = QComboBox()
        self.ua_combo.addItems(_UA_PROFILES)
        current_ua = self.settings.get('user_agent_profile', 'chrome_windows')
        if current_ua in _UA_PROFILES:
            self.ua_combo.setCurrentText(current_ua)
        g_layout.addWidget(self.ua_combo)

        g_layout.addWidget(QLabel("Кеш сканирования (GeoIP + пассивные субдомены):"))
        btn_clear_cache = StyledButton("Очистить кеш", style='secondary')
        btn_clear_cache.setToolTip(
            "Сбрасывает TTL-кеш GeoIP и пассивного перечисления субдоменов,\n"
            "чтобы следующий скан пошёл в сеть за свежими данными."
        )
        btn_clear_cache.clicked.connect(self._clear_cache)
        g_layout.addWidget(btn_clear_cache)

        group.setLayout(g_layout)
        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _build_output_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = SectionGroupBox("Архивация")
        g_layout = QVBoxLayout()
        self.auto_compress_cb = QCheckBox("Авто-архивация результатов")
        self.auto_compress_cb.setChecked(self.settings.get('auto_compress', False))
        g_layout.addWidget(self.auto_compress_cb)

        g_layout.addWidget(QLabel("Формат архива:"))
        self.compress_combo = QComboBox()
        self.compress_combo.addItems(_ARCHIVE_FORMATS)
        current_fmt = self.settings.get('compression_format', 'zip')
        if current_fmt in _ARCHIVE_FORMATS:
            self.compress_combo.setCurrentText(current_fmt)
        self.compress_combo.setToolTip(
            "RAR требует winrar/rar в PATH; иначе автоматически используется ZIP."
        )
        g_layout.addWidget(self.compress_combo)
        group.setLayout(g_layout)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _clear_cache(self):
        """Сбросить in-memory TTL-кеши сканирования (GeoIP + пассивные субдомены)."""
        from core.recon_engine import clear_geo_cache
        from core.subdomain_scanner import clear_passive_cache
        n = clear_geo_cache() + clear_passive_cache()
        QMessageBox.information(self, "Кеш", f"Очищено записей кеша: {n}")

    def _browse_output_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку", self.output_dir_edit.text())
        if path:
            self.output_dir_edit.setText(path)

    def _on_accept(self):
        # Expand ~ on save so an in-session scan never writes to a literal
        # "~" folder in the CWD (load_settings expands too, but only on next
        # launch — this closes the same-session gap).
        self.settings['output_dir'] = os.path.expanduser(
            self.output_dir_edit.text())
        self.settings['max_pages'] = self.max_pages_spin.value()
        self.settings['request_delay'] = self.delay_spin.value()
        self.settings['user_agent_profile'] = self.ua_combo.currentText()
        self.settings['auto_compress'] = self.auto_compress_cb.isChecked()
        self.settings['compression_format'] = self.compress_combo.currentText()
        self._save_settings()
        self.accept()

    def get_settings(self) -> dict:
        return self.settings.copy()
