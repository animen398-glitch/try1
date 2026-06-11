"""gui/window_chrome.py

The window frame ("chrome"): menu bar, the central tab container (built from
the plugin registry), and the status bar — plus the menu-driven dialogs
(settings / about) and the startup environment checks that surface messages
into that status bar. Folded into MainWindow as a mixin.

The host window is expected to provide:
  • ``self.settings``        dict — current settings (read/written here)
  • ``self._on_tab_changed`` slot — lazy-load hook wired to the tab widget
and, after _build_central runs, this mixin sets ``self.tabs``, ``self.plugins``,
``self._plugin_errors``; after _build_statusbar, ``self.status_bar``,
``self.task_indicator``, ``self.progress_bar``.
"""

import shutil

from PyQt5.QtWidgets import (
    QAction, QLabel, QMessageBox, QProgressBar, QStatusBar, QTabWidget,
    QVBoxLayout, QWidget,
)

from core import features
from gui.constants import PLUGINS_DIR
from gui.dialogs import SettingsDialog
from gui.plugin_manager import default_manager


class WindowChromeMixin:
    """Builds the menu / central tabs / status bar and their dialogs."""

    def _build_menu(self):
        menu = self.menuBar()

        file_menu = menu.addMenu("Файл")
        act_settings = QAction("Настройки...", self)
        act_settings.setShortcut("Ctrl+,")
        act_settings.triggered.connect(self._open_settings)
        file_menu.addAction(act_settings)
        file_menu.addSeparator()
        act_exit = QAction("Выход", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        help_menu = menu.addMenu("Помощь")
        act_about = QAction("О программе", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)

        self.tabs = QTabWidget()
        # Tabs are built from the plugin registry (single source of truth for
        # the tab bar), not a hard-coded addTab() list. Built-in tabs first,
        # then any external tab plugins dropped into PLUGINS_DIR. See
        # gui/plugin_manager.
        self.plugins = default_manager()
        self._plugin_errors: list = []
        self.plugins.discover(
            PLUGINS_DIR,
            on_error=lambda name, exc: self._plugin_errors.append((name, exc)),
        )
        self.plugins.build_into(self, self.tabs)
        layout.addWidget(self.tabs)

        # Lazily load history the first time its tab is opened.
        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _build_statusbar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.task_indicator = QLabel("")
        self.task_indicator.setStyleSheet("color: #4fc3f7; padding-right: 8px;")
        self.status_bar.addPermanentWidget(self.task_indicator)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Готов")

    def _report_plugin_errors(self):
        """Surface any external plugin that failed to load (non-fatal)."""
        errors = getattr(self, '_plugin_errors', [])
        if not errors:
            return
        names = ', '.join(name for name, _ in errors)
        self.status_bar.showMessage(
            f"Плагины не загружены: {names} (см. подробности в логах)", 10000
        )

    def _check_dependencies(self):
        fmt = self.settings.get('compression_format', 'zip')
        if fmt == 'rar' and not (shutil.which('rar') or shutil.which('winrar')):
            self.settings['compression_format'] = 'zip'
            self.status_bar.showMessage(
                "Внимание: WinRAR/rar не найден в PATH — архивация автоматически переключена на ZIP",
                10000,
            )
            return
        missing = features.missing()
        if missing:
            self.status_bar.showMessage(
                "Опциональные возможности недоступны: " + ", ".join(missing)
                + " (см. README по установке)", 10000,
            )

    def _open_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_():
            self.settings = dialog.get_settings()

    def _show_about(self):
        QMessageBox.about(
            self,
            "О программе",
            "Advanced Site Analyzer v1.0\n\n"
            "• Поиск утечек API ключей\n"
            "• Захват структуры сайтов\n"
            "• Загрузка видео (yt-dlp)\n"
            "• Извлечение изображений"
        )
