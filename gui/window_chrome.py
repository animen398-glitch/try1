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

from qtpy.QtCore import QTimer
from qtpy.QtWidgets import QLabel, QMessageBox, QProgressBar

from gui._fluent import FluentIcon, NavigationItemPosition

from core import features
from gui.constants import PLUGINS_DIR
from gui.dialogs import SettingsDialog
from gui.fluent_nav import (FluentWindowTabs, StatusBar, install_status_bar)
from gui.plugin_manager import default_manager


class WindowChromeMixin:
    """Builds the menu / central tabs / status bar and their dialogs."""

    def _build_menu(self):
        # FluentWindow has no menu bar — the menu actions live in the navigation
        # footer (Settings / About), with Exit at the very bottom.
        nav = self.navigationInterface
        # onClick is wired to the item's clicked(bool) signal, so swallow the arg.
        nav.addItem(routeKey='settings', icon=FluentIcon.SETTING,
                    text="Настройки", onClick=lambda *_: self._open_settings(),
                    selectable=False, position=NavigationItemPosition.BOTTOM)
        nav.addItem(routeKey='health', icon=FluentIcon.HEART,
                    text="Состояние системы", onClick=lambda *_: self._show_health(),
                    selectable=False, position=NavigationItemPosition.BOTTOM)
        nav.addItem(routeKey='about', icon=FluentIcon.INFO,
                    text="О программе", onClick=lambda *_: self._show_about(),
                    selectable=False, position=NavigationItemPosition.BOTTOM)
        nav.addItem(routeKey='exit', icon=FluentIcon.CLOSE,
                    text="Выход", onClick=lambda *_: self.close(),
                    selectable=False, position=NavigationItemPosition.BOTTOM)

    def _build_central(self):
        # FluentWindow owns the side navigation + content stack; self.tabs is a
        # QTabWidget-compatible facade over them, so the plugin contract, the
        # lazy-load hook and the GUI tests keep working unchanged.
        self.tabs = FluentWindowTabs(self)
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

        # Mount the status bar (built first) beneath the nav+content row.
        install_status_bar(self, self.status_bar)

        # Lazily load a tab's data the first time it is opened.
        self.tabs.currentChanged.connect(self._on_tab_changed)
        # The first tab is now a lazy one (Dashboard) and currentChanged does not
        # fire for the initial selection — trigger its load once the event loop is
        # running. Deferred via singleShot so headless tests (which never exec the
        # loop) don't spawn the load; the real app loads the first tab on startup.
        QTimer.singleShot(0, lambda: self._on_tab_changed(self.tabs.currentIndex()))

    def _build_statusbar(self):
        self.status_bar = StatusBar()
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
        if dialog.exec():
            self.settings = dialog.get_settings()

    def _show_health(self):
        """System-health screen (reuses the launcher's health engine)."""
        from gui.first_run import show_health_dialog
        show_health_dialog(self)

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
