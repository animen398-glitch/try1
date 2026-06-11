from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtWidgets import QFileDialog, QLineEdit, QMainWindow

from core import config
from gui.task_runner import TaskRunnerMixin
from gui.window_chrome import WindowChromeMixin
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


class MainWindow(QMainWindow, TaskRunnerMixin, WindowChromeMixin,
                 SystemTabMixin, ApiTabMixin,
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

    # The window chrome (menu / central tabs / status bar + settings/about
    # dialogs + startup dependency checks) lives in
    # gui/window_chrome.py:WindowChromeMixin.

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

    def _save_target(self, url: str):
        config.save_target(url)
