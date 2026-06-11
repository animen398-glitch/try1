import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QAction, QFileDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QStatusBar, QTabWidget, QVBoxLayout, QWidget,
)

from core import config, features
from gui.dialogs import SettingsDialog
from gui.constants import PLUGINS_DIR
from gui.plugin_manager import default_manager
from gui.task_runner import TaskRunnerMixin
from gui.tab_system import SystemTabMixin
from gui.tab_api import ApiTabMixin
from gui.tab_capture import CaptureTabMixin
from gui.tab_design import DesignTabMixin
from gui.tab_media import ImageTabMixin, VideoTabMixin
from gui.tab_recon import ReconTabMixin
from gui.tab_subdomain import SubdomainTabMixin
from gui.tab_clone import CloneTabMixin
from gui.tab_collection import FinalReportTabMixin
from gui.tab_cookie import CookieAuditTabMixin
from gui.tab_dashboard import DashboardTabMixin
from gui.tab_history import HistoryTabMixin
from utils.file_compression import FileCompressor
from utils.task_manager import TaskManager


class MainWindow(QMainWindow, TaskRunnerMixin, SystemTabMixin, ApiTabMixin,
                 VideoTabMixin, ImageTabMixin, CaptureTabMixin,
                 DesignTabMixin, ReconTabMixin, SubdomainTabMixin,
                 CloneTabMixin, CookieAuditTabMixin, FinalReportTabMixin,
                 DashboardTabMixin, HistoryTabMixin):
    """Основное окно Advanced Site Analyzer"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Site Analyzer")
        self.setMinimumSize(900, 650)
        self.settings = self._load_settings()
        # Single source of truth for every running background task.
        # Maps task_id -> _TaskHandle; entries are added in _start_task and
        # removed only after the OS thread has fully exited. All concurrency
        # safety (no GC of a live QThread) flows through this one dict.
        self._tasks: dict = {}
        self._next_task_id: int = 0
        self._last_recon_combined: dict = {}
        self._active_subdomain_scanner = None
        self._subdomain_rows: dict = {}
        self._active_capturer = None
        self._active_cloner = None
        self._active_collector = None
        self._history_rows: list = []
        self._history_loading = False
        self._history_view_cleared = False
        self._dashboard_loading = False
        self._dashboard_table_loading = False
        self._dashboard_filter_pending = False
        self._dashboard_loaded = False
        self._endpoint_filter = None  # active endpoint occurrence filter (or None)
        self.task_manager = TaskManager()

        self._build_menu()
        self._build_central()
        self._build_statusbar()
        self._check_dependencies()
        self._report_plugin_errors()

    # ------------------------------------------------------------------ setup

    def _load_settings(self) -> dict:
        return config.load_settings()

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

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _domain_slug(url: str) -> str:
        netloc = urlparse(url).netloc or url.split('/')[0]
        return netloc.replace('www.', '').replace(':', '_').strip('.') or 'unknown'

    @staticmethod
    def _folder_size(path: Path) -> int:
        return sum(f.stat().st_size for f in path.rglob('*') if f.is_file())

    @staticmethod
    def _fmt_size(nbytes: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if nbytes < 1024:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024
        return f"{nbytes:.2f} TB"

    def _make_archive(self, source_dir: Path, domain: str, suffix: str) -> Optional[str]:
        if not source_dir.exists() or not any(source_dir.rglob('*')):
            return None
        fmt = self.settings.get('compression_format', 'zip')
        name = f"{domain}_{datetime.now().strftime('%Y%m%d')}_{suffix}.{fmt}"
        out = str(source_dir.parent / name)
        try:
            return FileCompressor.to_rar(source_dir, out) if fmt == 'rar' else FileCompressor.to_zip(source_dir, out)
        except Exception:
            return None

    def _save_video_log(self, out_path: Path, url: str, status: str):
        try:
            log_file = out_path / 'video_links.txt'
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] {status} | {url}\n")
            self.video_results.append_info(f"Лог ссылок: {log_file}")
        except Exception:
            pass

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

    # The background-task runner (_start_task / _run_async / lifecycle) lives in
    # gui/task_runner.py:TaskRunnerMixin. closeEvent stays here as the Qt
    # override and just delegates to the mixin's thread-drain helper.

    def closeEvent(self, event):
        self._await_running_tasks()
        super().closeEvent(event)

    def _set_busy(self, busy: bool):
        self.progress_bar.setVisible(busy)
        if busy:
            self.progress_bar.setRange(0, 0)
            self.status_bar.showMessage("Выполняется...")
        else:
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage("Готов")

    def _browse(self, line_edit: QLineEdit):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку", line_edit.text())
        if path:
            line_edit.setText(path)

    def _browse_file(self, line_edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", line_edit.text())
        if path:
            line_edit.setText(path)

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

    def _save_target(self, url: str):
        config.save_target(url)
