import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import (
    QAction, QFileDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QStatusBar, QTabWidget, QVBoxLayout, QWidget,
)

from gui.dialogs import SettingsDialog
from gui.workers import _TaskHandle, _Worker
from gui.constants import SETTINGS_FILE, TARGETS_FILE
from gui.tab_system import SystemTabMixin
from gui.tab_api import ApiTabMixin
from gui.tab_capture import CaptureTabMixin
from gui.tab_design import DesignTabMixin
from gui.tab_media import ImageTabMixin, VideoTabMixin
from gui.tab_recon import ReconTabMixin
from gui.tab_subdomain import SubdomainTabMixin
from gui.tab_clone import CloneTabMixin
from gui.tab_cookie import CookieAuditTabMixin
from gui.tab_dashboard import DashboardTabMixin
from gui.tab_history import HistoryTabMixin
from utils.file_compression import FileCompressor
from utils.task_manager import TaskManager


class MainWindow(QMainWindow, SystemTabMixin, ApiTabMixin,
                 VideoTabMixin, ImageTabMixin, CaptureTabMixin,
                 DesignTabMixin, ReconTabMixin, SubdomainTabMixin,
                 CloneTabMixin, CookieAuditTabMixin, DashboardTabMixin,
                 HistoryTabMixin):
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
        self._active_capturer = None
        self._active_cloner = None
        self._history_rows: list = []
        self._history_loading = False
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

    # ------------------------------------------------------------------ setup

    def _load_settings(self) -> dict:
        try:
            if SETTINGS_FILE.exists():
                data = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
                data['output_dir'] = os.path.expanduser(
                    data.get('output_dir', '~/SiteAnalyzer')
                )
                return data
        except Exception:
            pass
        return {
            'output_dir': os.path.join(os.path.expanduser('~'), 'SiteAnalyzer'),
            'max_pages': 50,
            'request_delay': 500,
            'user_agent_profile': 'chrome_windows',
            'auto_compress': False,
            'compression_format': 'zip',
        }

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
        self.tabs.addTab(self._build_recon_tab(),      "Recon & Intel")
        self.tabs.addTab(self._build_subdomain_tab(),  "Subdomain Scanner")
        self.tabs.addTab(self._build_api_tab(),        "API Key Scanner")
        self.tabs.addTab(self._build_capture_tab(),    "Site Capture")
        self.tabs.addTab(self._build_clone_tab(),      "Clone Frontend")
        self.tabs.addTab(self._build_video_tab(),      "Video Downloader")
        self.tabs.addTab(self._build_image_tab(),      "Image Extractor")
        self.tabs.addTab(self._build_design_tab(),     "Design Lab")
        self.tabs.addTab(self._build_cookie_tab(),     "Cookie Security Audit")
        self.tabs.addTab(self._build_dashboard_tab(),  "Dashboard")
        self.tabs.addTab(self._build_history_tab(),    "История операций")
        self.tabs.addTab(self._build_system_tab(),     "System")
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

    def _update_task_indicator(self):
        """Reflect the number of live background tasks in the status bar."""
        n = len(self._tasks)
        self.task_indicator.setText(f"⚙ Активных задач: {n}" if n else "")

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

    # ───────────────────────────── task runner ──────────────────────────────
    #
    # Every background job — generic _Worker, capture, subdomain, clone — is
    # launched through _start_task. It owns the full QThread lifecycle and the
    # Signals/Slots wiring that decouples the GUI from the worker, so call
    # sites only describe *what* to run and *how* to react, never the plumbing.

    def _start_task(self, worker, *, on_finished=None, on_error=None,
                    signals=None) -> int:
        """Run ``worker`` on its own QThread with safe, centralised teardown.

        ``worker`` must expose a ``run()`` slot plus ``finished`` and ``error``
        signals. Cross-thread coupling is pure Signals/Slots:

          • ``on_finished(payload)`` — slot for the worker's ``finished`` signal.
          • ``on_error(message)``    — slot for the worker's ``error`` signal.
          • ``signals``              — iterable of ``(signal, slot)`` pairs for
                                       any extra worker signals (log, progress,
                                       row_found, …).

        The (worker, thread) pair is held in ``self._tasks`` until the OS thread
        has genuinely exited, then both are ``deleteLater``-d and the handle is
        dropped. Returns the task id.
        """
        thread = QThread()
        worker.moveToThread(thread)

        task_id = self._next_task_id
        self._next_task_id += 1
        self._tasks[task_id] = _TaskHandle(task_id, worker, thread)
        self._update_task_indicator()

        thread.started.connect(worker.run)

        # Caller-supplied reactions (queued across the thread boundary).
        if on_finished is not None:
            worker.finished.connect(on_finished)
        if on_error is not None:
            worker.error.connect(on_error)
        for sig, slot in (signals or ()):
            sig.connect(slot)

        # Stop the event loop on either terminal signal …
        worker.finished.connect(thread.quit)
        worker.error.connect(thread.quit)
        # … then tear everything down only after the OS thread has stopped.
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda tid=task_id: (self._tasks.pop(tid, None),
                                 self._update_task_indicator())
        )

        thread.start()
        return task_id

    def _on_worker_error(self):
        """Re-enable any action buttons that were disabled before a failed task."""
        for attr in ('btn_clone_run', 'dash_scan_btn'):
            btn = getattr(self, attr, None)
            if btn is not None:
                btn.setEnabled(True)

    def _run_async(self, fn, on_done):
        """Convenience wrapper: run ``fn()`` off-thread and deliver its result."""
        self._start_task(
            _Worker(fn),
            on_finished=on_done,
            on_error=lambda e: (
                self._set_busy(False),
                QMessageBox.critical(self, "Ошибка", e),
                self._on_worker_error(),
            ),
        )

    def closeEvent(self, event):
        # Wait for in-flight worker threads so none is destroyed mid-run.
        threads = [h.thread for h in list(self._tasks.values())]
        for thread in threads:
            if thread.isRunning():
                thread.quit()
        for thread in threads:
            if thread.isRunning():
                thread.wait(5000)
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
        try:
            TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
            targets = []
            if TARGETS_FILE.exists():
                targets = json.loads(TARGETS_FILE.read_text(encoding='utf-8'))
            if url not in targets:
                targets.insert(0, url)
                targets = targets[:100]
            TARGETS_FILE.write_text(json.dumps(targets, indent=2), encoding='utf-8')
        except Exception:
            pass
