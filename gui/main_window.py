import csv
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QAction, QCheckBox, QComboBox, QFileDialog,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMenuBar, QMessageBox, QProgressBar, QStatusBar,
    QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.api_key_extractor import ApiKeyExtractor
from core.api_dumper import ApiDumper
from core.content_capture import SiteContentCapture
from core.design_analyzer import DesignAnalyzer
from core.dynamic_analyzer import DynamicAnalyzer
from core.frontend_cloner import FrontendCloner
from utils.image_processor import ImageExtractor
from core.paywall_bypass import PaywallBypass
from core.recon_engine import ReconEngine, enrich_cms_with_dynamic
from core.subdomain_scanner import SubdomainScanner
from utils.video_processor import VideoDownloader
from core.vuln_scanner import VulnScanner
from gui.dialogs import SettingsDialog
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from utils.file_compression import FileCompressor
from utils.operation_registry import OperationRegistry
from utils.data_viewer import DataViewer
from utils.task_manager import TaskManager
from utils.exporter import DataExporter
from utils.endpoint_index import EndpointIndex
from utils.site_extractor import SiteExtractor
from utils.system_logger import get_last_logs

SETTINGS_FILE = Path(__file__).parent.parent / 'configs' / 'settings.json'
TARGETS_FILE = Path(__file__).parent.parent / 'configs' / 'targets.json'
OPERATIONS_DB = Path(__file__).parent.parent / 'data' / 'operations.db'
REGISTRY_DB = Path(__file__).parent.parent / 'data' / 'registry.db'
LIVE_TEST_OUTPUT = Path(__file__).parent.parent / 'live_test_output'


class _Worker(QObject):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.finished.emit(result if isinstance(result, dict) else {'result': result})
        except Exception as e:
            self.error.emit(str(e))


class _SubdomainWorker(QObject):
    row_found = pyqtSignal(dict)
    progress  = pyqtSignal(int, int)
    finished  = pyqtSignal(dict)
    error     = pyqtSignal(str)

    def __init__(self, scanner, domain: str, passive: bool, brute: bool):
        super().__init__()
        self._scanner = scanner
        self._domain  = domain
        self._passive = passive
        self._brute   = brute

    def run(self):
        try:
            result = self._scanner.scan(
                self._domain,
                on_found=lambda entry: self.row_found.emit(entry),
                on_progress=lambda cur, tot: self.progress.emit(cur, tot),
                passive=self._passive,
                brute=self._brute,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class _CloneWorker(QObject):
    """Thread worker for FrontendCloner with real-time log + page progress."""
    log_message = pyqtSignal(str)
    progress    = pyqtSignal(int, int)   # (current_page, total_pages)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, cloner):
        super().__init__()
        self._cloner  = cloner
        self._total   = 0
        self._current = 0

    def run(self):
        try:
            self._cloner.set_progress_callback(self._on_msg)
            result = self._cloner.clone()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

    def _on_msg(self, msg: str):
        self.log_message.emit(msg)
        if 'HTML файлов для обработки:' in msg:
            try:
                self._total = int(msg.split(':')[-1].strip())
                self._current = 0
                self.progress.emit(0, self._total)
            except ValueError:
                pass
        elif 'Локализую:' in msg:
            self._current += 1
            self.progress.emit(self._current, self._total)


class _CaptureWorker(QObject):
    """Thread worker for SiteContentCapture with thread-safe log routing."""
    log_message = pyqtSignal(str)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, capturer):
        super().__init__()
        self._capturer = capturer

    def run(self):
        try:
            self._capturer.set_progress_callback(lambda msg: self.log_message.emit(msg))
            result = self._capturer.run_capture()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class _TaskHandle:
    """Strong-reference holder for one (worker, thread) pair.

    Every background task lives entirely inside one of these. Keeping both the
    QThread *and* its worker referenced here — and releasing them only after
    the OS thread has actually finished (``thread.finished`` → ``deleteLater``)
    — is what prevents the "QThread: Destroyed while thread is still running"
    crash. Each task gets its own handle, so any number can run concurrently
    without one overwriting another's reference.
    """
    __slots__ = ('id', 'worker', 'thread')

    def __init__(self, task_id: int, worker: QObject, thread: QThread):
        self.id = task_id
        self.worker = worker
        self.thread = thread


class MainWindow(QMainWindow):
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

    # ---------------------------------------------------------------- System

    def _build_system_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── Task queue ───────────────────────────────────────────────────
        q_grp = SectionGroupBox("Очередь задач")
        q = QVBoxLayout()
        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.task_url = QLineEdit()
        self.task_url.setPlaceholderText("https://example.com")
        self.task_url.returnPressed.connect(self._add_task_to_queue)
        btn_add = StyledButton("Add to Queue")
        btn_add.clicked.connect(self._add_task_to_queue)
        row.addWidget(self.task_url)
        row.addWidget(btn_add)
        q.addLayout(row)
        self.task_queue_label = QLabel("В очереди: 0")
        self.task_queue_label.setStyleSheet("color:#888; font-size:11px;")
        q.addWidget(self.task_queue_label)
        q_grp.setLayout(q)
        layout.addWidget(q_grp)

        # ── Export ───────────────────────────────────────────────────────
        e_grp = SectionGroupBox("Экспорт данных (DataRegistry)")
        e = QHBoxLayout()
        btn_csv = StyledButton("Export CSV", style='secondary')
        btn_csv.clicked.connect(lambda: self._export_data('csv'))
        btn_json = StyledButton("Export JSON", style='secondary')
        btn_json.clicked.connect(lambda: self._export_data('json'))
        btn_endpoints = StyledButton("Export Endpoints", style='secondary')
        btn_endpoints.clicked.connect(self._export_endpoints)
        e.addWidget(btn_csv)
        e.addWidget(btn_json)
        e.addWidget(btn_endpoints)
        e.addStretch()
        e_grp.setLayout(e)
        layout.addWidget(e_grp)

        # ── Logs ─────────────────────────────────────────────────────────
        l_grp = SectionGroupBox("Системные логи (последние 50)")
        l = QVBoxLayout()
        self.system_logs = ResultsDisplay()
        l.addWidget(self.system_logs)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_logs)
        l.addWidget(btn_refresh)
        l_grp.setLayout(l)
        layout.addWidget(l_grp, stretch=1)

        self._refresh_logs()
        return w

    def _add_task_to_queue(self):
        url = self.task_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return
        try:
            self.task_manager.add_task(url)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить задачу: {e}")
            return
        self.task_url.clear()
        self.task_queue_label.setText(f"В очереди: {self.task_manager.queue.qsize()}")
        self.status_bar.showMessage(f"Задача добавлена: {url}")
        self._refresh_logs()

    def _refresh_logs(self):
        try:
            lines = get_last_logs(50)
        except Exception as e:
            lines = [f"Ошибка чтения логов: {e}\n"]
        self.system_logs.setPlainText(''.join(lines))
        scrollbar = self.system_logs.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _export_data(self, fmt: str):
        suffix = fmt.lower()
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить экспорт", f"registry_export.{suffix}",
            f"{fmt.upper()} (*.{suffix})",
        )
        if not path:
            return
        try:
            ok = DataExporter.export(path, format=suffix)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))
            return
        if ok:
            QMessageBox.information(self, "Экспорт", f"Данные сохранены:\n{path}")
        else:
            QMessageBox.warning(self, "Экспорт", "Нет данных для экспорта")

    def _export_endpoints(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт API-эндпоинтов", "api_endpoints.json",
            "JSON (*.json);;CSV (*.csv)",
        )
        if not path:
            return
        suffix = 'csv' if path.lower().endswith('.csv') else 'json'
        try:
            ok = DataExporter.export(path, format=suffix, data_type='api_endpoint')
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))
            return
        if not ok:
            QMessageBox.warning(self, "Экспорт", "Нет эндпоинтов для экспорта")
            return
        # Дедуплицированная сводка для информативного сообщения.
        try:
            s = EndpointIndex(db_path=str(REGISTRY_DB)).get_summary()
            extra = (f"\n\nЗаписей: {s['total_records']} | "
                     f"уникальных эндпоинтов: {s['unique_endpoints']}")
        except Exception:
            extra = ""
        QMessageBox.information(self, "Экспорт", f"Эндпоинты сохранены:\n{path}{extra}")

    # ------------------------------------------------------------- Dashboard

    DASHBOARD_COLUMNS = ["Data Type", "Source", "Snippet"]

    # (ключ summary -> подпись карточки)
    DASHBOARD_STATS = [
        ('subdomains',    'Субдомены'),
        ('ips',           'IP-адреса'),
        ('images',        'Изображения'),
        ('videos',        'Видео'),
        ('patterns',      'Паттерны'),
        ('api_endpoints', 'API Endpoints'),
    ]

    # (подпись фильтра -> data_type; None = последние записи всех типов)
    DASHBOARD_FILTERS = [
        ('Последние (все типы)', None),
        ('Субдомены',            'subdomain'),
        ('IP-адреса',            'ip_address'),
        ('Изображения',          'image'),
        ('Видео',                'video'),
        ('Паттерны',             'pattern_match'),
        ('API Endpoints',        'api_endpoint'),
    ]

    ENDPOINTS_COLUMNS = ["Endpoint", "Count", "Sources", "Patterns"]

    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        self.dash_status = QLabel("Всего записей: 0")
        btn_update = StyledButton("Обновить", style='secondary')
        btn_update.clicked.connect(self._refresh_dashboard)
        ctrl.addWidget(self.dash_status)
        ctrl.addStretch()
        ctrl.addWidget(btn_update)
        layout.addLayout(ctrl)

        # Scan control — runs SiteExtractor on a URL, then refreshes the dashboard.
        scan_grp = SectionGroupBox("Сканировать страницу")
        scan_row = QHBoxLayout()
        scan_row.addWidget(QLabel("URL:"))
        self.dash_scan_url = QLineEdit()
        self.dash_scan_url.setPlaceholderText("https://example.com")
        self.dash_scan_url.returnPressed.connect(self._run_dashboard_scan)
        self.dash_scan_btn = StyledButton("Run Scan")
        self.dash_scan_btn.clicked.connect(self._run_dashboard_scan)
        scan_row.addWidget(self.dash_scan_url)
        scan_row.addWidget(self.dash_scan_btn)
        scan_grp.setLayout(scan_row)
        layout.addWidget(scan_grp)

        stats_row = QHBoxLayout()
        self.dash_stats: dict = {}
        for key, title in self.DASHBOARD_STATS:
            card, value_label = self._make_stat_card(title)
            self.dash_stats[key] = value_label
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        table_grp = SectionGroupBox("Записи реестра (data/registry.db)")
        self._activity_grp = table_grp
        table_layout = QVBoxLayout()

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Фильтр по типу:"))
        self.dash_filter = QComboBox()
        for label, dtype in self.DASHBOARD_FILTERS:
            self.dash_filter.addItem(label, dtype)
        # Подключаем после заполнения, чтобы не сработало во время сборки UI.
        self.dash_filter.currentIndexChanged.connect(self._on_filter_combo_changed)
        filter_row.addWidget(self.dash_filter)
        filter_row.addStretch()
        table_layout.addLayout(filter_row)

        self.dashboard_table = QTableWidget(0, len(self.DASHBOARD_COLUMNS))
        self.dashboard_table.setHorizontalHeaderLabels(self.DASHBOARD_COLUMNS)
        self.dashboard_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dashboard_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dashboard_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.dashboard_table.verticalHeader().setVisible(False)
        self.dashboard_table.setAlternatingRowColors(True)
        header = self.dashboard_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Snippet fills space
        table_layout.addWidget(self.dashboard_table)
        table_grp.setLayout(table_layout)
        layout.addWidget(table_grp, stretch=1)

        ep_grp = SectionGroupBox("Уникальные API-эндпоинты (дедуплицировано)")
        ep_layout = QVBoxLayout()
        self.endpoints_table = QTableWidget(0, len(self.ENDPOINTS_COLUMNS))
        self.endpoints_table.setHorizontalHeaderLabels(self.ENDPOINTS_COLUMNS)
        self.endpoints_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.endpoints_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.endpoints_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.endpoints_table.verticalHeader().setVisible(False)
        self.endpoints_table.setAlternatingRowColors(True)
        ep_header = self.endpoints_table.horizontalHeader()
        ep_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        ep_header.setSectionResizeMode(0, QHeaderView.Stretch)  # Endpoint fills space
        self.endpoints_table.itemSelectionChanged.connect(self._on_endpoint_row_selected)
        ep_layout.addWidget(self.endpoints_table)
        ep_grp.setLayout(ep_layout)
        layout.addWidget(ep_grp, stretch=1)

        self._dashboard_widget = w
        return w

    def _make_stat_card(self, title: str):
        card = SectionGroupBox(title)
        v = QVBoxLayout()
        value_label = QLabel("0")
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet(
            "font-size: 28px; font-weight: bold; color: #0078d4;"
        )
        v.addWidget(value_label)
        card.setLayout(v)
        return card, value_label

    def _run_dashboard_scan(self):
        url = self.dash_scan_url.text().strip()
        if not url:
            self.dash_status.setText("Укажите URL для сканирования")
            return
        self.dash_scan_btn.setEnabled(False)
        self._set_busy(True)
        self.dash_status.setText(f"Сканирование: {url} ...")
        self._run_async(lambda u=url: self._scan_pipeline(u), self._on_scan_done)

    @staticmethod
    def _scan_pipeline(url: str) -> dict:
        # Runs entirely off the GUI thread; SiteExtractor records any findings
        # (patterns/endpoints) to DataRegistry. Guarded so failures surface as
        # data rather than an unhandled crash.
        try:
            return {'scan': SiteExtractor().fetch_text(url)}
        except Exception as e:
            return {'error': str(e)}

    def _on_scan_done(self, result: dict):
        self.dash_scan_btn.setEnabled(True)
        if result.get('error'):
            self._set_busy(False)
            self.dash_status.setText(f"Ошибка сканирования: {result['error']}")
            return
        scan = result.get('scan', {})
        status = scan.get('status', '')
        if status != 'Success':
            self._set_busy(False)
            self.dash_status.setText(f"Сканирование завершилось: {status}")
            return
        # Success → refresh stats + tables so the new data shows immediately.
        found = scan.get('patterns_found', 0)
        self.dash_status.setText(f"Сканирование завершено (находок: {found}). Обновляю...")
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        if self._dashboard_loading:
            return
        self._dashboard_loading = True
        self._set_busy(True)
        self._run_async(self._query_dashboard, self._on_dashboard_loaded)

    @staticmethod
    def _query_dashboard() -> dict:
        # Constructed inside the worker thread so the SQLite connection is
        # opened, used, and closed entirely off the GUI thread. All retrieval
        # is guarded so a DB error surfaces as data, never an unhandled crash.
        try:
            viewer = DataViewer(db_path=str(REGISTRY_DB))
            endpoints = EndpointIndex(db_path=str(REGISTRY_DB)).get_unique_endpoints()
            return {'summary': viewer.get_summary(), 'endpoints': endpoints}
        except Exception as e:
            return {'error': str(e)}

    def _on_dashboard_loaded(self, result: dict):
        self._dashboard_loading = False
        self._set_busy(False)

        if result.get('error'):
            self._dashboard_loaded = False  # allow retry on next open/refresh
            self.dash_status.setText(f"Ошибка загрузки данных: {result['error']}")
            return

        self._dashboard_loaded = True
        summary = result.get('summary', {})
        for key, label in self.dash_stats.items():
            label.setText(str(summary.get(key, 0)))
        self.dash_status.setText(f"Всего записей: {summary.get('total', 0)}")

        # A full refresh resets any drill-down back to the type-filter view.
        self._endpoint_filter = None
        self._update_activity_title()
        self._populate_endpoints_table(result.get('endpoints', []))

        # Populate the table according to the currently selected type filter.
        self._apply_dashboard_filter()

    def _populate_endpoints_table(self, endpoints: list):
        self.endpoints_table.setRowCount(0)
        for ep in endpoints[:200]:
            r = self.endpoints_table.rowCount()
            self.endpoints_table.insertRow(r)
            sources = ep.get('sources', [])
            patterns = ep.get('patterns', [])
            values = [
                ep.get('endpoint', ''),
                ep.get('count', 0),
                ep.get('source_count', 0),
                ', '.join(patterns),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col in (1, 2):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if col == 2 and sources:
                    item.setToolTip('\n'.join(sources))  # source pages on hover
                self.endpoints_table.setItem(r, col, item)

    def _on_filter_combo_changed(self, *args):
        # A manual type change clears any active endpoint drill-down.
        self._endpoint_filter = None
        self._update_activity_title()
        self._apply_dashboard_filter()

    def _apply_dashboard_filter(self, *args):
        # Never run two table queries at once: remember that the filter
        # changed and re-run once the in-flight query comes back.
        if self._dashboard_table_loading:
            self._dashboard_filter_pending = True
            return
        self._dashboard_table_loading = True
        self._set_busy(True)
        data_type = self.dash_filter.currentData()
        endpoint = self._endpoint_filter
        self._run_async(
            lambda dt=data_type, ep=endpoint: self._query_dashboard_table(dt, ep),
            self._on_dashboard_table_loaded,
        )

    @staticmethod
    def _query_dashboard_table(data_type, endpoint=None) -> dict:
        # Off-GUI-thread read; guarded so a DB error surfaces as data. The
        # data_type/endpoint are echoed back so a stale result can be discarded.
        try:
            viewer = DataViewer(db_path=str(REGISTRY_DB))
            if endpoint:
                # Raw occurrences of one normalized endpoint (all its variants).
                rows = [
                    r for r in viewer.get_by_type('api_endpoint')
                    if EndpointIndex.normalize(r.get('content', '')) == endpoint
                ][:200]
            elif data_type:
                rows = viewer.get_by_type(data_type)[:200]
            else:
                rows = viewer.get_recent_records(limit=20)
            return {'rows': rows, 'data_type': data_type, 'endpoint': endpoint}
        except Exception as e:
            return {'error': str(e), 'data_type': data_type, 'endpoint': endpoint}

    def _on_dashboard_table_loaded(self, result: dict):
        self._dashboard_table_loading = False
        self._set_busy(False)
        # A filter change arrived while this query was running: its result is
        # stale by definition, so just re-run with the current selection.
        if self._dashboard_filter_pending:
            self._dashboard_filter_pending = False
            self._apply_dashboard_filter()
            return
        # Discard results whose filter no longer matches the current selection.
        if (result.get('data_type') != self.dash_filter.currentData()
                or result.get('endpoint') != self._endpoint_filter):
            return
        if result.get('error'):
            self.dash_status.setText(f"Ошибка загрузки таблицы: {result['error']}")
            return
        self._populate_dashboard_table(result.get('rows', []))

    def _on_endpoint_row_selected(self):
        rows = self.endpoints_table.selectionModel().selectedRows()
        if not rows:
            return
        item = self.endpoints_table.item(rows[0].row(), 0)
        if item is None:
            return
        self._endpoint_filter = item.text()
        # Keep the type combo consistent (api_endpoint) without re-firing it.
        api_idx = next(
            (i for i, (_, dt) in enumerate(self.DASHBOARD_FILTERS)
             if dt == 'api_endpoint'),
            None,
        )
        if api_idx is not None and self.dash_filter.currentIndex() != api_idx:
            self.dash_filter.blockSignals(True)
            self.dash_filter.setCurrentIndex(api_idx)
            self.dash_filter.blockSignals(False)
        self._update_activity_title()
        self._apply_dashboard_filter()

    def _update_activity_title(self):
        if self._endpoint_filter:
            self._activity_grp.setTitle(f"Вхождения эндпоинта: {self._endpoint_filter}")
        else:
            self._activity_grp.setTitle("Записи реестра (data/registry.db)")

    def _populate_dashboard_table(self, records: list):
        self.dashboard_table.setRowCount(0)
        for rec in records:
            r = self.dashboard_table.rowCount()
            self.dashboard_table.insertRow(r)
            content = rec.get('content') or ''
            snippet = content if len(content) <= 80 else content[:77] + '...'
            values = [rec.get('data_type', ''), rec.get('source', ''), snippet]
            meta = rec.get('metadata')
            context = meta.get('context') if isinstance(meta, dict) else None
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 2 and context:
                    item.setToolTip(str(context))  # full context on hover
                self.dashboard_table.setItem(r, col, item)

    # ------------------------------------------------------- Operation History

    HISTORY_COLUMNS = ["ID", "Target", "Phase", "Status", "Started At", "Duration (ms)"]

    def _build_history_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        self.history_count = QLabel("Записей: 0")
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_history)
        ctrl.addWidget(self.history_count)
        ctrl.addStretch()
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        table_grp = SectionGroupBox("История операций (data/operations.db)")
        table_layout = QVBoxLayout()
        self.history_table = QTableWidget(0, len(self.HISTORY_COLUMNS))
        self.history_table.setHorizontalHeaderLabels(self.HISTORY_COLUMNS)
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setAlternatingRowColors(True)
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Target column fills space
        self.history_table.itemSelectionChanged.connect(self._on_history_row_selected)
        table_layout.addWidget(self.history_table)
        table_grp.setLayout(table_layout)
        layout.addWidget(table_grp, stretch=3)

        meta_grp = SectionGroupBox("Метаданные выбранной операции")
        meta_layout = QVBoxLayout()
        self.history_meta = ResultsDisplay()
        self.history_meta.setMaximumHeight(180)
        meta_layout.addWidget(self.history_meta)
        meta_grp.setLayout(meta_layout)
        layout.addWidget(meta_grp, stretch=1)

        self._history_widget = w
        return w

    def _on_tab_changed(self, index: int):
        widget = self.tabs.widget(index)
        if widget is getattr(self, '_history_widget', None):
            if not self._history_rows and not self._history_loading:
                self._refresh_history()
        elif widget is getattr(self, '_dashboard_widget', None):
            if not self._dashboard_loaded and not self._dashboard_loading:
                self._refresh_dashboard()

    def _refresh_history(self):
        if self._history_loading:
            return
        self._history_loading = True
        self._set_busy(True)
        self._run_async(self._query_history, self._on_history_loaded)

    @staticmethod
    def _query_history() -> dict:
        # Constructed inside the worker thread so the SQLite connection is
        # opened, used, and closed entirely off the GUI thread.
        registry = OperationRegistry(db_path=str(OPERATIONS_DB))
        return {'rows': registry.history(limit=1000)}

    def _on_history_loaded(self, result: dict):
        self._history_loading = False
        self._set_busy(False)
        rows = result.get('rows', [])
        self._history_rows = rows

        self.history_table.setRowCount(0)
        for row in rows:
            r = self.history_table.rowCount()
            self.history_table.insertRow(r)
            values = [
                row.get('id'),
                row.get('target'),
                row.get('phase'),
                row.get('status'),
                row.get('started_at'),
                row.get('duration_ms'),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem('' if val is None else str(val))
                if col in (0, 5):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if col == 3:  # Status colouring
                    status = (row.get('status') or '').lower()
                    if status == 'success':
                        item.setForeground(QColor('#2e7d32'))
                    elif status == 'failed':
                        item.setForeground(QColor('#d32f2f'))
                    elif status == 'running':
                        item.setForeground(QColor('#0078d4'))
                self.history_table.setItem(r, col, item)

        self.history_count.setText(f"Записей: {len(rows)}")
        self.history_meta.clear()
        if not rows:
            self.history_meta.append_info("История пуста — операции ещё не записаны.")

    def _on_history_row_selected(self):
        rows = self.history_table.selectionModel().selectedRows()
        self.history_meta.clear()
        if not rows:
            return
        idx = rows[0].row()
        if not (0 <= idx < len(self._history_rows)):
            return
        record = self._history_rows[idx]

        error = record.get('error')
        if error:
            self.history_meta.append_error(error)

        metadata = record.get('metadata')
        if metadata in (None, '', {}):
            self.history_meta.append_info("Метаданные отсутствуют.")
            return
        try:
            text = json.dumps(metadata, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(metadata)
        self.history_meta.append(f'<pre style="color:#d4d4d4;margin:0;">{text}</pre>')

    # --------------------------------------------------------- API Key Scanner

    def _build_api_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Целевой URL")
        row = QHBoxLayout()
        self.api_url = QLineEdit()
        self.api_url.setPlaceholderText("https://example.com")
        self.api_url.returnPressed.connect(self._run_api_scan)
        btn = StyledButton("Сканировать")
        btn.clicked.connect(self._run_api_scan)
        row.addWidget(self.api_url)
        row.addWidget(btn)
        grp.setLayout(row)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Результаты")
        res_layout = QVBoxLayout()
        self.api_results = ResultsDisplay()
        res_layout.addWidget(self.api_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_api_scan(self):
        url = self.api_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Введите URL")
            return
        self.api_results.clear()
        self.api_results.append_info(f"Начинаю сканирование: {url}")
        self._set_busy(True)

        extractor = ApiKeyExtractor()
        extractor.set_target_url(url)
        extractor.set_profile(self.settings.get('user_agent_profile', 'chrome_windows'))
        self._run_async(extractor.run_extraction, self._on_api_done)

    def _on_api_done(self, result: dict):
        self._set_busy(False)
        status = result.get('status', '')
        if status == 'Success':
            found = result.get('keys_found', 0)
            self.api_results.append_success(f"Статус: {status} | Найдено: {found}")
            details = result.get('details', {})
            if details:
                for key_type, keys in details.items():
                    self.api_results.append_warning(f"[{key_type}]:")
                    for k in keys:
                        self.api_results.append(f"  • {k}")
            else:
                self.api_results.append_info("Утечек не обнаружено")
        else:
            self.api_results.append_error(f"Ошибка: {status}")
        self._save_target(self.api_url.text().strip())

    # ----------------------------------------------------------- Site Capture

    def _build_capture_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Настройки захвата")
        g = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("URL:"))
        self.capture_url = QLineEdit()
        self.capture_url.setPlaceholderText("https://example.com")
        row1.addWidget(self.capture_url)
        g.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Папка:"))
        self.capture_dir = QLineEdit(self.settings.get('output_dir', ''))
        btn_browse = StyledButton("...", style='secondary')
        btn_browse.setMaximumWidth(40)
        btn_browse.clicked.connect(lambda: self._browse(self.capture_dir))
        row2.addWidget(self.capture_dir)
        row2.addWidget(btn_browse)
        g.addLayout(row2)

        btn_row = QHBoxLayout()
        self.btn_capture_start = StyledButton("Начать захват")
        self.btn_capture_start.clicked.connect(self._run_capture)
        self.btn_capture_stop = StyledButton("Остановить", style='secondary')
        self.btn_capture_stop.setEnabled(False)
        self.btn_capture_stop.clicked.connect(self._stop_capture)
        btn_row.addWidget(self.btn_capture_start)
        btn_row.addWidget(self.btn_capture_stop)
        g.addLayout(btn_row)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Лог захвата")
        res_layout = QVBoxLayout()
        self.capture_log = ResultsDisplay()
        res_layout.addWidget(self.capture_log)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_capture(self):
        url = self.capture_url.text().strip()
        base_out = self.capture_dir.text().strip()
        if not url or not base_out:
            QMessageBox.warning(self, "Ошибка", "Укажите URL и папку")
            return

        domain = self._domain_slug(url)
        out_path = Path(base_out) / f"{domain}_{datetime.now().strftime('%Y%m%d')}"

        self.capture_log.clear()
        self.capture_log.append_info(f"Начинаю захват: {url}")
        self.capture_log.append_info(f"Директория: {out_path}")
        self._set_busy(True)

        capturer = SiteContentCapture()
        capturer.configure(
            url, str(out_path),
            self.settings.get('max_pages', 50),
            profile=self.settings.get('user_agent_profile', 'chrome_windows'),
        )
        self._active_capturer = capturer
        self.btn_capture_start.setEnabled(False)
        self.btn_capture_stop.setEnabled(True)

        worker = _CaptureWorker(capturer)
        self._start_task(
            worker,
            on_finished=lambda r, _p=out_path, _d=domain: self._on_capture_done(r, _p, _d),
            on_error=lambda e: (self._reset_capture_buttons(),
                                self._set_busy(False),
                                QMessageBox.critical(self, "Ошибка захвата", e)),
            signals=[(worker.log_message, self.capture_log.append_info)],
        )

    def _stop_capture(self):
        if getattr(self, '_active_capturer', None):
            self._active_capturer.cancel()
            self.capture_log.append_warning("Останавливаю захват…")
        self.btn_capture_stop.setEnabled(False)

    def _reset_capture_buttons(self):
        self._active_capturer = None
        self.btn_capture_start.setEnabled(True)
        self.btn_capture_stop.setEnabled(False)

    def _on_capture_done(self, result: dict, out_path: Path, domain: str):
        self._reset_capture_buttons()
        if result.get('cancelled'):
            self.capture_log.append_warning("Захват отменён пользователем")
        self._set_busy(False)
        self.capture_log.append_success(
            f"Захвачено страниц: {result.get('pages_captured', 0)}"
        )
        self.capture_log.append_info(f"Директория: {out_path}")

        if out_path.exists():
            size = self._folder_size(out_path)
            self.capture_log.append_info(f"Объём данных: {self._fmt_size(size)}")

        if result.get('errors'):
            self.capture_log.append_warning(
                f"Недоступных URL при обходе: {len(result['errors'])}"
            )

        archive = self._make_archive(out_path, domain, 'capture')
        if archive:
            self.capture_log.append_success(f"Архив создан: {Path(archive).name}")
        else:
            self.capture_log.append_warning("Архивация пропущена — папка пуста или не найдена")

        files = [str(p) for p in out_path.glob('**/*') if p.is_file()] if out_path.exists() else []
        if files:
            stats = self._analyse_capture_files(files)
            self.capture_log.append('')
            self.capture_log.append(
                f'<span style="color:#ff5252;font-weight:bold;">[🚨]</span>'
                f' Найдено потенциальных утечек ключей: {stats["key_leaks"]}'
            )
            self.capture_log.append(
                f'<span style="color:#4fc3f7;">[ℹ️]</span>'
                f' Найдено комментариев разработчиков: {stats["comments"]}'
            )
            self.capture_log.append(
                f'<span style="color:#81c784;">[📂]</span>'
                f' Обнаружены скрытые/технические пути: {stats["hidden_paths"]}'
            )

    _KEY_RE = re.compile(
        r'(?:'
        r'sk-[A-Za-z0-9]{20,}'
        r'|AIza[A-Za-z0-9_\-]{35}'
        r'|AKIA[A-Z0-9]{16}'
        r'|ghp_[A-Za-z0-9]{36}'
        r'|xox[baprs]-[A-Za-z0-9\-]+'
        r'|(?:api[_\-]?key|apikey|api_token|access_token|secret_key)'
        r'(?:["\'\s:=]+)[A-Za-z0-9_\-]{16,}'
        r'|[Bb]earer\s+[A-Za-z0-9._\-]{20,}'
        r')'
    )
    _COMMENT_RE = re.compile(r'<!--(.{8,}?)-->', re.DOTALL)
    _HIDDEN_RE  = re.compile(
        r'(?:href|src|action)=["\'][^"\']*'
        r'(?:/admin|/api/|/debug|/test|/staging|\.env|/config'
        r'|/internal|/swagger|/graphql|/phpmyadmin|/wp-admin|/manage|/console)',
        re.IGNORECASE,
    )

    def _analyse_capture_files(self, files: list) -> dict:
        key_leaks   = 0
        comments    = 0
        hidden_paths = 0
        seen_keys   : set = set()
        seen_paths  : set = set()
        for filepath in files:
            try:
                text = Path(filepath).read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            for m in self._KEY_RE.finditer(text):
                token = m.group(0)[:60]
                if token not in seen_keys:
                    seen_keys.add(token)
                    key_leaks += 1
            comments += len(self._COMMENT_RE.findall(text))
            for m in self._HIDDEN_RE.finditer(text):
                hit = m.group(0)
                if hit not in seen_paths:
                    seen_paths.add(hit)
                    hidden_paths += 1
        return {'key_leaks': key_leaks, 'comments': comments, 'hidden_paths': hidden_paths}

    # --------------------------------------------------------- Video Download

    def _build_video_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Загрузка видео (yt-dlp)")
        g = QVBoxLayout()

        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.video_url = QLineEdit()
        self.video_url.setPlaceholderText("https://youtube.com/watch?v=...")
        self.video_url.returnPressed.connect(self._run_video)
        row.addWidget(self.video_url)
        g.addLayout(row)

        btn_dl = StyledButton("Скачать", style='success')
        btn_dl.clicked.connect(self._run_video)
        g.addWidget(btn_dl)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Статус")
        res_layout = QVBoxLayout()
        self.video_results = ResultsDisplay()
        res_layout.addWidget(self.video_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_video(self):
        url = self.video_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return

        domain = self._domain_slug(url)
        out_path = LIVE_TEST_OUTPUT / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_video"

        self.video_results.clear()
        self.video_results.append_info(f"Загружаю: {url}")
        self.video_results.append_info(f"Директория: {out_path}")
        self._set_busy(True)

        dl = VideoDownloader()

        def _on_done(result, _p=out_path, _u=url):
            self._on_video_done(result, _p, _u)

        self._run_async(lambda: dl.download_video(url, out_path), _on_done)

    def _on_video_done(self, result: dict, out_path: Path, url: str):
        self._set_busy(False)
        status = result.get('status', '')
        if status == 'Success':
            self.video_results.append_success("Загрузка завершена")
            self.video_results.append_info(f"Директория: {out_path}")
            if 'output' in result:
                self.video_results.append(result['output'][:500])
        else:
            self.video_results.append_error(f"Ошибка: {status}")
        self._save_video_log(out_path, url, status)

    # -------------------------------------------------------- Image Extractor

    def _build_image_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Извлечение изображений")
        g = QVBoxLayout()

        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.image_url = QLineEdit()
        self.image_url.setPlaceholderText("https://example.com")
        self.image_url.returnPressed.connect(self._run_images)
        row.addWidget(self.image_url)
        g.addLayout(row)

        btn_ex = StyledButton("Извлечь изображения")
        btn_ex.clicked.connect(self._run_images)
        g.addWidget(btn_ex)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Найденные изображения")
        res_layout = QVBoxLayout()
        self.image_results = ResultsDisplay()
        res_layout.addWidget(self.image_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_images(self):
        url = self.image_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return

        domain = self._domain_slug(url)
        out_path = LIVE_TEST_OUTPUT / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_images"

        self.image_results.clear()
        self.image_results.append_info(f"Сканирую: {url}")
        self.image_results.append_info(f"Директория: {out_path}")
        self._set_busy(True)

        ex = ImageExtractor(profile=self.settings.get('user_agent_profile', 'chrome_windows'))
        ex.set_progress_callback(lambda msg: self.image_results.append_info(msg))

        def _on_done(result, _p=out_path, _d=domain):
            self._on_images_done(result, _p, _d)

        self._run_async(lambda: ex.extract_images(url, out_path), _on_done)

    def _on_images_done(self, result: dict, out_path: Path, domain: str):
        self._set_busy(False)
        found = result.get('found', 0)
        downloaded = result.get('downloaded', 0)
        self.image_results.append_success(f"Найдено: {found} | Загружено: {downloaded}")
        self.image_results.append_info(
            f"Отфильтровано — дубликатов: {result.get('duplicates', 0)} | "
            f"мелких (< 2KB): {result.get('skipped_small', 0)}"
        )
        self.image_results.append_info(f"Директория: {out_path}")

        if out_path.exists():
            size = self._folder_size(out_path)
            self.image_results.append_info(f"Объём данных: {self._fmt_size(size)}")

        if result.get('failed'):
            self.image_results.append_warning(
                f"Не удалось загрузить: {len(result['failed'])} файл(а)"
            )
            for f in result['failed'][:5]:
                self.image_results.append_error(f"  {f}")

        archive = self._make_archive(out_path, domain, 'images')
        if archive:
            self.image_results.append_success(f"Архив создан: {Path(archive).name}")
        else:
            self.image_results.append_warning("Архивация пропущена — нет скачанных файлов")

    # ------------------------------------------------------------ Design Lab

    def _build_design_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        src_grp = SectionGroupBox("Источник анализа")
        src_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Директория с захваченными файлами:"))
        self.design_dir = QLineEdit(self.settings.get('output_dir', ''))
        btn_browse = StyledButton("...", style='secondary')
        btn_browse.setMaximumWidth(40)
        btn_browse.clicked.connect(lambda: self._browse(self.design_dir))
        row1.addWidget(self.design_dir)
        row1.addWidget(btn_browse)
        src_layout.addLayout(row1)

        row2 = QHBoxLayout()
        btn_run = StyledButton("Запустить анализ")
        btn_run.clicked.connect(self._run_design_analysis)
        btn_load = StyledButton("Загрузить palette.json", style='secondary')
        btn_load.clicked.connect(self._load_palette_from_dir)
        self.design_stats_label = QLabel("")
        self.design_stats_label.setStyleSheet("color:#888; font-size:11px; padding-left:8px;")
        row2.addWidget(btn_run)
        row2.addWidget(btn_load)
        row2.addStretch()
        row2.addWidget(self.design_stats_label)
        src_layout.addLayout(row2)

        src_grp.setLayout(src_layout)
        layout.addWidget(src_grp)

        results_row = QHBoxLayout()

        colors_grp = SectionGroupBox("Цветовая палитра")
        cl = QVBoxLayout()
        self.design_colors = ResultsDisplay()
        cl.addWidget(self.design_colors)
        colors_grp.setLayout(cl)

        fonts_grp = SectionGroupBox("Типографика")
        fl = QVBoxLayout()
        self.design_fonts = ResultsDisplay()
        fl.addWidget(self.design_fonts)
        fonts_grp.setLayout(fl)

        results_row.addWidget(colors_grp, 3)
        results_row.addWidget(fonts_grp, 2)
        layout.addLayout(results_row)

        cmp_grp = SectionGroupBox("Сравнение версий (анализ изменений)")
        cmp_layout = QVBoxLayout()

        rowa = QHBoxLayout()
        rowa.addWidget(QLabel("Папка A:"))
        self.design_cmp_a = QLineEdit()
        self.design_cmp_a.setPlaceholderText("Старая версия (папка с захваченными файлами)")
        btn_browse_a = StyledButton("...", style='secondary')
        btn_browse_a.setMaximumWidth(40)
        btn_browse_a.clicked.connect(lambda: self._browse(self.design_cmp_a))
        rowa.addWidget(self.design_cmp_a)
        rowa.addWidget(btn_browse_a)
        cmp_layout.addLayout(rowa)

        rowb = QHBoxLayout()
        rowb.addWidget(QLabel("Папка B:"))
        self.design_cmp_b = QLineEdit()
        self.design_cmp_b.setPlaceholderText("Новая версия (папка с захваченными файлами)")
        btn_browse_b = StyledButton("...", style='secondary')
        btn_browse_b.setMaximumWidth(40)
        btn_browse_b.clicked.connect(lambda: self._browse(self.design_cmp_b))
        rowb.addWidget(self.design_cmp_b)
        rowb.addWidget(btn_browse_b)
        cmp_layout.addLayout(rowb)

        btn_cmp = StyledButton("Сравнить")
        btn_cmp.clicked.connect(self._run_design_compare)
        cmp_layout.addWidget(btn_cmp)

        self.design_diff = ResultsDisplay()
        cmp_layout.addWidget(self.design_diff)

        cmp_grp.setLayout(cmp_layout)
        layout.addWidget(cmp_grp)

        self._design_show_placeholder()
        return w

    def _run_design_compare(self):
        path_a = self.design_cmp_a.text().strip()
        path_b = self.design_cmp_b.text().strip()
        if not path_a or not path_b:
            QMessageBox.warning(self, "Ошибка", "Укажите обе папки для сравнения")
            return

        self.design_diff.clear()
        self.design_diff.append_info(f"Сравниваю:\n  A: {path_a}\n  B: {path_b}")
        self._set_busy(True)

        analyzer = DesignAnalyzer()
        analyzer.set_progress_callback(lambda msg: self.design_diff.append_info(msg))
        self._run_async(
            lambda: analyzer.compare_versions(path_a, path_b),
            self._on_design_compare_done,
        )

    def _on_design_compare_done(self, result: dict):
        self._set_busy(False)
        status = result.get('status', '')
        if status != 'Success':
            self.design_diff.append_error(f"Ошибка: {status}")
            return

        s = result.get('summary', {})
        self.design_diff.append_success(
            f"Added: {s.get('added', 0)}  |  "
            f"Modified: {s.get('modified', 0)}  |  "
            f"Removed: {s.get('removed', 0)}  |  "
            f"Unchanged: {s.get('unchanged', 0)}"
        )
        for f in result.get('added', [])[:25]:
            self.design_diff.append(f'<span style="color:#81c784;">[+]</span> {f}')
        for f in result.get('modified', [])[:25]:
            self.design_diff.append(f'<span style="color:#ffb74d;">[~]</span> {f}')
        for f in result.get('removed', [])[:25]:
            self.design_diff.append(f'<span style="color:#e57373;">[-]</span> {f}')

    def _run_design_analysis(self):
        source = self.design_dir.text().strip()
        if not source:
            QMessageBox.warning(self, "Ошибка", "Укажите директорию")
            return
        self.design_colors.clear()
        self.design_fonts.clear()
        self.design_colors.append_info(f"Анализирую: {source}")
        self._set_busy(True)

        analyzer = DesignAnalyzer()
        analyzer.configure(source)
        analyzer.set_progress_callback(lambda msg: self.design_colors.append_info(msg))

        self._run_async(analyzer.analyze, self._on_design_done)

    def _on_design_done(self, result: dict):
        self._set_busy(False)
        status = result.get('status', '')
        if status == 'Success':
            self._render_palette(result)
            stats = result.get('stats', {})
            self.design_stats_label.setText(
                f"Цветов: {stats.get('total_colors', 0)}  |  "
                f"Шрифтов: {stats.get('total_fonts', 0)}  |  "
                f"Файлов: {stats.get('css_files', 0)} CSS, {stats.get('html_files', 0)} HTML"
            )
        elif 'Warning' in status:
            self._design_show_placeholder()
            self.design_colors.append_warning(status)
        else:
            self.design_colors.append_error(f"Ошибка: {status}")

    def _load_palette_from_dir(self):
        source = self.design_dir.text().strip()
        if not source:
            QMessageBox.warning(self, "Ошибка", "Укажите директорию")
            return
        palette_path = Path(source) / 'ui_palette.json'
        if not palette_path.exists():
            self._design_show_placeholder()
            return
        try:
            data = json.loads(palette_path.read_text(encoding='utf-8'))
            self._render_palette(data)
            stats = data.get('stats', {})
            self.design_stats_label.setText(
                f"Цветов: {stats.get('total_colors', 0)}  |  "
                f"Шрифтов: {stats.get('total_fonts', 0)}"
            )
        except Exception as e:
            self.design_colors.append_error(f"Ошибка чтения palette.json: {e}")

    # ------------------------------------------------------------ Recon & Intel

    def _build_recon_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Цель и параметры разведки")
        g = QVBoxLayout()

        row_url = QHBoxLayout()
        row_url.addWidget(QLabel("URL:"))
        self.recon_url = QLineEdit()
        self.recon_url.setPlaceholderText("https://example.com")
        self.recon_url.returnPressed.connect(self._run_recon)
        row_url.addWidget(self.recon_url)
        g.addLayout(row_url)

        row_opts = QHBoxLayout()
        self.chk_dynamic = QCheckBox("Dynamic API Sniffing")
        self.chk_dynamic.setToolTip(
            "Запускает headless Chromium (Playwright) для перехвата XHR/Fetch запросов.\n"
            "Требует: pip install playwright && python -m playwright install chromium"
        )
        self.chk_paywall = QCheckBox("Paywall Bypass")
        self.chk_paywall.setToolTip(
            "Последовательно применяет Googlebot-спуфинг, вырезание JS-блоков\n"
            "и запрос архивного снимка Wayback Machine."
        )
        btn_run = StyledButton("Запустить Recon")
        btn_run.clicked.connect(self._run_recon)
        self.btn_dump_api = StyledButton("Dump Full API Responses", style='secondary')
        self.btn_dump_api.setToolTip(
            "Сохраняет все перехваченные API endpoints, JSON-структуры и секреты\n"
            "в папку на диске. Требует выполнения Dynamic API Sniffing."
        )
        self.btn_dump_api.setEnabled(False)
        self.btn_dump_api.clicked.connect(self._run_dump_api)
        row_opts.addWidget(self.chk_dynamic)
        row_opts.addSpacing(12)
        row_opts.addWidget(self.chk_paywall)
        row_opts.addStretch()
        row_opts.addWidget(self.btn_dump_api)
        row_opts.addSpacing(8)
        row_opts.addWidget(btn_run)
        g.addLayout(row_opts)

        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Результаты разведки")
        res_layout = QVBoxLayout()
        self.recon_results = ResultsDisplay()
        res_layout.addWidget(self.recon_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_recon(self):
        url = self.recon_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Введите URL")
            return

        self.recon_results.clear()
        self.recon_results.append_info(f"Запускаю разведку: {url}")
        self._set_busy(True)

        do_dynamic = self.chk_dynamic.isChecked()
        do_paywall = self.chk_paywall.isChecked()
        output_dir = self.settings.get('output_dir', str(Path.home() / 'SiteAnalyzer'))
        profile    = self.settings.get('user_agent_profile', 'chrome_windows')

        log = self.recon_results   # safe reference for closure

        def _work():
            combined: dict = {'url': url, 'recon': {}, 'dynamic': {}, 'paywall': {}}

            # ── Phase 1: GeoIP + CMS + favicons (always) ──────────────────
            engine = ReconEngine()
            engine.configure(profile=profile)
            combined['recon'] = engine.run_recon(url)

            # ── Phase 2: Paywall bypass (optional) ────────────────────────
            if do_paywall:
                log.append_info("Запускаю Paywall Bypass...")
                bypass = PaywallBypass()
                bypass.configure()
                pw = bypass.extract(url)
                if pw.get('html'):
                    domain = self._domain_slug(url)
                    out_file = (
                        Path(output_dir)
                        / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}_bypass.html"
                    )
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_text(pw['html'], encoding='utf-8')
                    pw['saved_to'] = str(out_file)
                combined['paywall'] = {k: v for k, v in pw.items() if k != 'html'}

            # ── Phase 3: Dynamic traffic interception (optional) ──────────
            if do_dynamic:
                analyzer = DynamicAnalyzer()
                analyzer.configure(timeout_ms=25000, wait_ms=3000)
                analyzer.set_progress_callback(lambda msg: log.append_info(msg))
                combined['dynamic'] = analyzer.analyze_dynamic_traffic(url)
                if combined['dynamic'].get('status') == 'Success':
                    enrich_cms_with_dynamic(combined['recon'], combined['dynamic'])

            # ── Phase 4: Vulnerability scan (always) ──────────────────────
            combined['vulns'] = VulnScanner().scan(
                combined.get('recon', {}), combined.get('dynamic', {})
            )

            return combined

        self._run_async(_work, self._on_recon_done)

    def _on_recon_done(self, result: dict):
        self._set_busy(False)
        D = "─" * 52

        # ── GeoIP + infrastructure ────────────────────────────────────────
        recon = result.get('recon', {})
        if recon.get('status') == 'Success':
            self.recon_results.append_info(D)
            geo = recon.get('geo', {})

            if recon.get('ip'):
                self.recon_results.append(f"  IP Address   : {recon['ip']}")
            if geo.get('country'):
                region = geo.get('regionName', '')
                city   = geo.get('city', '?')
                loc    = f"{city}, {region}, {geo['country']}" if region else f"{city}, {geo['country']}"
                self.recon_results.append(f"  Location     : {loc}")
            if geo.get('isp'):
                self.recon_results.append(f"  ISP          : {geo['isp']}")
            if geo.get('as'):
                self.recon_results.append(f"  ASN          : {geo['as']}")
            if geo.get('org') and geo.get('org') != geo.get('isp'):
                self.recon_results.append(f"  Organisation : {geo['org']}")

            # Server headers
            for k, v in recon.get('server_headers', {}).items():
                self.recon_results.append(f"  {k:<13}: {v}")

            # CMS / tech stack — extended
            self.recon_results.append_info(D)
            cms         = recon.get('cms', [])
            cms_details = recon.get('cms_details', {})
            if cms:
                self.recon_results.append_success(
                    f"  Stack detected ({len(cms)}):"
                )
                for fw in cms:
                    self.recon_results.append_success(f"    [+] {fw}")
                    for indicator in cms_details.get(fw, [])[:3]:
                        self.recon_results.append_info(
                            f"         indicator : {indicator}"
                        )
            else:
                self.recon_results.append("  CMS / Stack  : не определён")

            # Favicons
            favicons = recon.get('favicons', [])
            if favicons:
                self.recon_results.append_info(f"  Favicons ({len(favicons)}):")
                for fav in favicons[:6]:
                    self.recon_results.append(f"    • [{fav['type']}]  {fav['url']}")

            # PWA manifest
            manifest = recon.get('pwa_manifest', {})
            if manifest:
                name = manifest.get('data', {}).get('name', 'PWA')
                self.recon_results.append_success(
                    f"  PWA Manifest : {name}  ({manifest.get('url', '')})"
                )
        else:
            self.recon_results.append_error(
                f"  Recon: {recon.get('error', 'неизвестная ошибка')}"
            )

        # ── Paywall bypass ────────────────────────────────────────────────
        paywall = result.get('paywall', {})
        if paywall:
            self.recon_results.append_info(D)
            paywalled = paywall.get('paywalled', False)
            strategy  = paywall.get('strategy_used') or '—'
            pw_status = paywall.get('status', 'Failed')
            self.recon_results.append(
                f"  Paywall      : {'Обнаружен' if paywalled else 'Не обнаружен'}"
            )
            if pw_status == 'Success':
                self.recon_results.append_success(f"  Bypass       : {strategy}")
                if paywall.get('saved_to'):
                    self.recon_results.append_info(f"  Сохранён в   : {paywall['saved_to']}")
            else:
                self.recon_results.append_warning("  Bypass       : все стратегии не сработали")

        # ── Dynamic analysis ──────────────────────────────────────────────
        dynamic = result.get('dynamic', {})
        if dynamic.get('status') == 'Success':
            self.recon_results.append_info(D)
            self.recon_results.append_success(
                f"  API-вызовов  : {dynamic['total_api_calls']} "
                f"({dynamic['unique_hosts']} уникальных хостов)"
            )

            endpoints = dynamic.get('endpoints', [])
            if endpoints:
                self.recon_results.append_info(f"  XHR / Fetch endpoints ({len(endpoints)}):")
                for ep in endpoints[:25]:
                    path   = ep.get('path', '/')[:48]
                    host   = ep.get('host', '')
                    method = ep.get('method', 'GET')
                    code   = ep.get('status', 0)
                    self.recon_results.append(
                        f"    {method:<5} {code:>3}  {path:<50}  {host}"
                    )
                if len(endpoints) > 25:
                    self.recon_results.append_info(
                        f"    … и ещё {len(endpoints) - 25} endpoints"
                    )

            auth_hdrs = dynamic.get('auth_headers', [])
            if auth_hdrs:
                self.recon_results.append_warning(
                    f"  Auth-заголовки ({len(auth_hdrs)}):"
                )
                for ah in auth_hdrs[:10]:
                    self.recon_results.append_warning(
                        f"    {ah['header']}: {ah['preview']}"
                        f"  [{ah['url'][-55:]}]"
                    )

            structs = dynamic.get('json_structures', [])

            # ── Secrets / tokens inside JSON payloads ─────────────────────
            payload_secrets = dynamic.get('secrets_found', [])
            if payload_secrets:
                self.recon_results.append_warning(D)
                self.recon_results.append_warning(
                    f"  [!!] SECRETS IN JSON PAYLOADS ({len(payload_secrets)}):"
                )
                for sec in payload_secrets[:20]:
                    self.recon_results.append_warning(
                        f"    [{sec['type']:<14}]  key='{sec['key']}'"
                        f"  =>  '{sec['preview']}'"
                    )
                    self.recon_results.append_info(
                        f"                    {sec['source_url'][-60:]}"
                    )

            # ── Runtime globals detected by Playwright JS probe ───────────
            runtime_globals = dynamic.get('runtime_globals', {})
            if runtime_globals:
                names = list(runtime_globals.keys())
                self.recon_results.append_success(
                    f"  Runtime globals ({len(names)}):"
                )
                for fw in names:
                    self.recon_results.append_success(f"    [window] {fw}")

            # ── JSON response structures with sample values ────────────────
            if structs:
                self.recon_results.append_info(
                    f"  JSON-структуры ответов ({len(structs)}):"
                )
                for js in structs[:10]:
                    keys   = js.get('top_keys') or js.get('item_keys', [])
                    suffix = f"  [array x {js['length']}]" if js.get('type') == 'array' else ''
                    url_s  = js.get('url', '')[-58:]
                    self.recon_results.append_info(f"    {url_s}{suffix}")
                    self.recon_results.append(f"      keys : {keys[:10]}")
                    for k, v in list(js.get('sample', {}).items())[:4]:
                        self.recon_results.append(
                            f"        {k:<20} : {str(v)[:60]}"
                        )

        elif dynamic.get('status') == 'Error':
            self.recon_results.append_info(D)
            self.recon_results.append_error(
                f"  Dynamic: {dynamic.get('error', '')}"
            )

        # ── Discovered Vulnerabilities ─────────────────────────────────────
        vulns = result.get('vulns', [])
        if vulns:
            self.recon_results.append_info(D)
            highs   = [v for v in vulns if v['severity'] == 'High']
            mediums = [v for v in vulns if v['severity'] == 'Medium']
            infos   = [v for v in vulns if v['severity'] == 'Info']
            self.recon_results.append(
                f"  Discovered Vulns: {len(highs)} High  |  "
                f"{len(mediums)} Medium  |  {len(infos)} Info"
            )
            for v in highs:
                self.recon_results.append_high(f"  {v['title']}")
                if v.get('detail'):
                    self.recon_results.append_info(f"    {v['detail'][:120]}")
            for v in mediums:
                self.recon_results.append_medium(f"  {v['title']}")
                if v.get('detail'):
                    self.recon_results.append_info(f"    {v['detail'][:120]}")
            for v in infos:
                self.recon_results.append_success(f"  {v['title']}")
                if v.get('detail'):
                    self.recon_results.append_info(f"    {v['detail'][:100]}")

        # Store result + activate dump button if dynamic data is present
        self._last_recon_combined = result
        self.btn_dump_api.setEnabled(
            result.get('dynamic', {}).get('status') == 'Success'
        )

        self.recon_results.append_info(D)
        self.recon_results.append_success("Разведка завершена")
        self._save_target(self.recon_url.text().strip())

    # --------------------------------------------------- API dump handlers

    def _run_dump_api(self):
        dynamic = self._last_recon_combined.get('dynamic', {})
        if dynamic.get('status') != 'Success':
            QMessageBox.information(
                self, "API Dump",
                "Сначала запустите сканирование с включённым 'Dynamic API Sniffing'.",
            )
            return
        output_dir = self.settings.get('output_dir', str(Path.home() / 'SiteAnalyzer'))
        url = self._last_recon_combined.get('url', '')
        dumper = ApiDumper()
        dumper.configure(output_dir)
        self.btn_dump_api.setEnabled(False)
        self.recon_results.append_info("Сохраняю полные API ответы на диск...")
        self._set_busy(True)
        _dyn = dynamic
        _url = url

        def _work():
            return dumper.dump(_dyn, _url)

        self._run_async(_work, self._on_dump_done)

    def _on_dump_done(self, result: dict):
        self._set_busy(False)
        self.btn_dump_api.setEnabled(True)
        if result.get('status') == 'Success':
            out = result['output_dir']
            self.recon_results.append_success(
                f"  Dump завершён — {result['files_written']} файлов, "
                f"{result['endpoint_count']} endpoints"
            )
            self.recon_results.append_info(f"  Папка: {out}")
            try:
                os.startfile(out)
            except Exception:
                pass
        else:
            self.recon_results.append_error(
                f"  Dump ошибка: {result.get('error', '')}"
            )

    # -------------------------------------------------------- Subdomain Scanner

    def _build_subdomain_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Target & Options")
        g = QVBoxLayout()

        row_domain = QHBoxLayout()
        row_domain.addWidget(QLabel("Domain:"))
        self.subdomain_domain = QLineEdit()
        self.subdomain_domain.setPlaceholderText("example.com")
        self.subdomain_domain.returnPressed.connect(self._run_subdomain_scan)
        row_domain.addWidget(self.subdomain_domain)
        g.addLayout(row_domain)

        row_opts = QHBoxLayout()
        self.subdomain_chk_passive = QCheckBox("Passive recon  (crt.sh + HackerTarget)")
        self.subdomain_chk_passive.setChecked(True)
        self.subdomain_chk_passive.setToolTip(
            "Queries certificate transparency logs and HackerTarget\n"
            "without sending any requests to the target domain."
        )
        self.subdomain_chk_brute = QCheckBox("DNS Brute Force")
        self.subdomain_chk_brute.setChecked(True)
        self.subdomain_chk_brute.setToolTip(
            "Resolves ~200 common subdomain names via DNS.\n"
            "Uses 40 concurrent threads for speed."
        )
        self.btn_subdomain_scan = StyledButton("Start Scanning")
        self.btn_subdomain_scan.clicked.connect(self._run_subdomain_scan)
        self.btn_subdomain_stop = StyledButton("Stop", style='danger')
        self.btn_subdomain_stop.setEnabled(False)
        self.btn_subdomain_stop.clicked.connect(self._stop_subdomain_scan)
        row_opts.addWidget(self.subdomain_chk_passive)
        row_opts.addSpacing(14)
        row_opts.addWidget(self.subdomain_chk_brute)
        row_opts.addStretch()
        row_opts.addWidget(self.btn_subdomain_stop)
        row_opts.addSpacing(8)
        row_opts.addWidget(self.btn_subdomain_scan)
        g.addLayout(row_opts)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Discovered Subdomains")
        res_layout = QVBoxLayout()

        hdr_row = QHBoxLayout()
        self.subdomain_status_lbl = QLabel("Ready")
        self.subdomain_status_lbl.setStyleSheet(
            "color:#4fc3f7; font-family:Consolas; font-size:12px; padding:2px 0;"
        )
        self.subdomain_progress = QProgressBar()
        self.subdomain_progress.setMaximumHeight(14)
        self.subdomain_progress.setVisible(False)
        self.subdomain_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555; border-radius: 3px;
                background: #2d2d2d; text-align: center; color: transparent;
            }
            QProgressBar::chunk { background: #0078d4; border-radius: 2px; }
        """)
        self.btn_subdomain_export = StyledButton("Export CSV", style='secondary')
        self.btn_subdomain_export.setEnabled(False)
        self.btn_subdomain_export.clicked.connect(self._export_subdomain_csv)
        hdr_row.addWidget(self.subdomain_status_lbl)
        hdr_row.addWidget(self.subdomain_progress, 1)
        hdr_row.addSpacing(8)
        hdr_row.addWidget(self.btn_subdomain_export)
        res_layout.addLayout(hdr_row)

        self.subdomain_table = QTableWidget(0, 4)
        self.subdomain_table.setHorizontalHeaderLabels(
            ["Subdomain", "IP Address", "Status", "Source"]
        )
        hdr = self.subdomain_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.subdomain_table.verticalHeader().setVisible(False)
        self.subdomain_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.subdomain_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.subdomain_table.setAlternatingRowColors(True)
        self.subdomain_table.setSortingEnabled(False)
        self.subdomain_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                alternate-background-color: #252525;
                color: #d4d4d4;
                border: 1px solid #555;
                border-radius: 4px;
                gridline-color: #333333;
                font-family: Consolas;
                font-size: 11px;
            }
            QTableWidget::item { padding: 3px 8px; }
            QTableWidget::item:selected {
                background-color: #0078d4; color: #ffffff;
            }
            QHeaderView::section {
                background-color: #2d2d2d;
                color: #4fc3f7;
                border: none;
                border-bottom: 2px solid #0078d4;
                padding: 5px 8px;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        res_layout.addWidget(self.subdomain_table)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_subdomain_scan(self):
        domain = self.subdomain_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "Error", "Enter a target domain (e.g. example.com)")
            return

        # Cancel any running scan first
        self._stop_subdomain_scan()

        self.subdomain_table.setSortingEnabled(False)
        self.subdomain_table.setRowCount(0)
        self.subdomain_status_lbl.setText("Starting…")
        self.subdomain_progress.setRange(0, 0)
        self.subdomain_progress.setVisible(True)
        self.btn_subdomain_scan.setEnabled(False)
        self.btn_subdomain_stop.setEnabled(True)
        self.btn_subdomain_export.setEnabled(False)

        passive = self.subdomain_chk_passive.isChecked()
        brute   = self.subdomain_chk_brute.isChecked()

        scanner = SubdomainScanner()
        self._active_subdomain_scanner = scanner

        worker = _SubdomainWorker(scanner, domain, passive, brute)
        self._start_task(
            worker,
            on_finished=self._on_subdomain_done,
            on_error=self._on_subdomain_error,
            signals=[
                (worker.row_found, self._on_subdomain_row_found),
                (worker.progress,  self._on_subdomain_progress),
            ],
        )

    def _stop_subdomain_scan(self):
        if self._active_subdomain_scanner:
            self._active_subdomain_scanner.cancel()
        self.btn_subdomain_stop.setEnabled(False)

    def _on_subdomain_row_found(self, entry: dict):
        row = self.subdomain_table.rowCount()
        self.subdomain_table.insertRow(row)

        col_data = [
            entry.get('subdomain', ''),
            entry.get('ip', ''),
            entry.get('status', ''),
            entry.get('source', ''),
        ]
        for col, text in enumerate(col_data):
            item = QTableWidgetItem(text)
            if col == 2:  # Status
                item.setForeground(
                    QColor('#81c784') if text == 'Live' else QColor('#888888')
                )
            elif col == 3:  # Source
                colours = {
                    'crt.sh': '#4fc3f7',
                    'hackertarget': '#4fc3f7',
                    'brute': '#ffb74d',
                }
                item.setForeground(QColor(colours.get(text, '#d4d4d4')))
            self.subdomain_table.setItem(row, col, item)

        count = self.subdomain_table.rowCount()
        self.subdomain_status_lbl.setText(f"Found: {count} subdomain(s)")

    def _on_subdomain_progress(self, current: int, total: int):
        if total == 0:
            self.subdomain_progress.setRange(0, 0)
        else:
            self.subdomain_progress.setRange(0, total)
            self.subdomain_progress.setValue(current)

    def _on_subdomain_done(self, result: dict):
        self._active_subdomain_scanner = None
        self.subdomain_progress.setVisible(False)
        self.btn_subdomain_scan.setEnabled(True)
        self.btn_subdomain_stop.setEnabled(False)
        total   = result.get('total', 0)
        elapsed = result.get('elapsed', 0)
        status  = result.get('status', 'Done')
        self.subdomain_status_lbl.setText(
            f"{status} — {total} subdomain(s) found  ({elapsed}s)"
        )
        if total:
            self.btn_subdomain_export.setEnabled(True)
            self.subdomain_table.setSortingEnabled(True)
            self.subdomain_table.sortByColumn(2, Qt.AscendingOrder)

    def _on_subdomain_error(self, msg: str):
        self._active_subdomain_scanner = None
        self.subdomain_progress.setVisible(False)
        self.btn_subdomain_scan.setEnabled(True)
        self.btn_subdomain_stop.setEnabled(False)
        self.subdomain_status_lbl.setText(f"Error: {msg}")

    def _export_subdomain_csv(self):
        domain = self.subdomain_domain.text().strip().replace('.', '_')
        default = (
            f"subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'IP Address', 'Status', 'Source'])
                for row in range(self.subdomain_table.rowCount()):
                    writer.writerow([
                        self.subdomain_table.item(row, c).text()
                        if self.subdomain_table.item(row, c) else ''
                        for c in range(4)
                    ])
            QMessageBox.information(self, "Export Complete", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ------------------------------------------------------------ Clone Frontend

    def _build_clone_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Cloner Settings")
        g = QVBoxLayout()
        g.setSpacing(8)

        # Source directory
        row_src = QHBoxLayout()
        row_src.addWidget(QLabel("Source Dir:"))
        self.clone_src = QLineEdit()
        self.clone_src.setPlaceholderText(
            "Folder with captured HTML files and site_map.json"
        )
        btn_browse_src = StyledButton("Browse…", style='secondary')
        btn_browse_src.setFixedWidth(90)
        btn_browse_src.clicked.connect(lambda: self._browse(self.clone_src))
        row_src.addWidget(self.clone_src)
        row_src.addWidget(btn_browse_src)
        g.addLayout(row_src)

        # Output directory (optional)
        row_out = QHBoxLayout()
        row_out.addWidget(QLabel("Output Dir:"))
        self.clone_out = QLineEdit()
        self.clone_out.setPlaceholderText(
            "Leave blank to auto-create <source>_cloned/ next to source"
        )
        btn_browse_out = StyledButton("Browse…", style='secondary')
        btn_browse_out.setFixedWidth(90)
        btn_browse_out.clicked.connect(lambda: self._browse(self.clone_out))
        row_out.addWidget(self.clone_out)
        row_out.addWidget(btn_browse_out)
        g.addLayout(row_out)

        # Action row
        row_act = QHBoxLayout()
        row_act.addStretch()
        self.btn_clone_run = StyledButton("Clone Frontend")
        self.btn_clone_run.clicked.connect(self._run_clone)
        self.btn_clone_stop = StyledButton("Stop", style='secondary')
        self.btn_clone_stop.setEnabled(False)
        self.btn_clone_stop.clicked.connect(self._stop_clone)
        row_act.addWidget(self.btn_clone_run)
        row_act.addWidget(self.btn_clone_stop)
        g.addLayout(row_act)

        grp.setLayout(g)
        layout.addWidget(grp)

        # Log / results
        res_grp = SectionGroupBox("Clone Log")
        res_layout = QVBoxLayout()

        hdr_row = QHBoxLayout()
        self.clone_status_lbl = QLabel("Ready")
        self.clone_status_lbl.setStyleSheet(
            "color:#4fc3f7; font-family:Consolas; font-size:12px; padding:2px 0;"
        )
        self.clone_progress = QProgressBar()
        self.clone_progress.setMaximumHeight(14)
        self.clone_progress.setVisible(False)
        self.clone_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555; border-radius: 3px;
                background: #2d2d2d; text-align: center; color: transparent;
            }
            QProgressBar::chunk { background: #0078d4; border-radius: 2px; }
        """)
        hdr_row.addWidget(self.clone_status_lbl)
        hdr_row.addWidget(self.clone_progress, 1)
        res_layout.addLayout(hdr_row)

        self.clone_log = ResultsDisplay()
        res_layout.addWidget(self.clone_log)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.btn_clone_open = StyledButton("Open Output Folder", style='secondary')
        self.btn_clone_open.setEnabled(False)
        self.btn_clone_open.clicked.connect(self._open_clone_output)
        btn_row.addWidget(self.btn_clone_open)
        res_layout.addLayout(btn_row)

        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_clone(self):
        src = self.clone_src.text().strip()
        if not src:
            QMessageBox.warning(self, "Clone Frontend", "Select a source directory first.")
            return
        if not Path(src).is_dir():
            QMessageBox.warning(self, "Clone Frontend",
                                f"Source directory not found:\n{src}")
            return

        out = self.clone_out.text().strip()
        if not out:
            out = str(Path(src).parent / (Path(src).name + '_cloned'))

        profile = self.settings.get('user_agent_profile', 'chrome_windows')

        self.clone_log.clear()
        self.clone_log.append_info(f"Source : {src}")
        self.clone_log.append_info(f"Output : {out}")
        self.clone_status_lbl.setText("Starting…")
        self.clone_progress.setRange(0, 0)
        self.clone_progress.setVisible(True)
        self.btn_clone_run.setEnabled(False)
        self.btn_clone_stop.setEnabled(True)
        self.btn_clone_open.setEnabled(False)
        self._set_busy(True)

        cloner = FrontendCloner()
        cloner.configure(src, out, profile=profile)
        self._active_cloner = cloner

        worker = _CloneWorker(cloner)
        self._start_task(
            worker,
            on_finished=self._on_clone_done,
            on_error=lambda e: (self._reset_clone_buttons(),
                                self._set_busy(False),
                                self.clone_progress.setVisible(False),
                                self.clone_status_lbl.setText("Error"),
                                QMessageBox.critical(self, "Clone Error", e)),
            signals=[
                (worker.log_message, self._on_clone_log),
                (worker.progress,    self._on_clone_progress),
            ],
        )

    def _stop_clone(self):
        if getattr(self, '_active_cloner', None):
            self._active_cloner.cancel()
            self.clone_log.append_warning("Stopping clone…")
        self.btn_clone_stop.setEnabled(False)

    def _reset_clone_buttons(self):
        self._active_cloner = None
        self.btn_clone_run.setEnabled(True)
        self.btn_clone_stop.setEnabled(False)

    def _on_clone_log(self, msg: str):
        m = msg.strip()
        if 'Ошибка' in m or 'Error' in m:
            self.clone_log.append_error(msg)
        elif m.startswith('Готово') or m.startswith('[OK]'):
            self.clone_log.append_success(msg)
        elif m.startswith('[') and ']' in m:
            self.clone_log.append(
                f'<span style="color:#888; font-family:Consolas;">{msg}</span>'
            )
        else:
            self.clone_log.append_info(msg)

    def _on_clone_progress(self, current: int, total: int):
        if total > 0:
            self.clone_progress.setRange(0, total)
            self.clone_progress.setValue(current)
            self.clone_status_lbl.setText(f"Page {current}/{total}")
        else:
            self.clone_progress.setRange(0, 0)

    def _on_clone_done(self, result: dict):
        self._set_busy(False)
        self._reset_clone_buttons()
        self.clone_progress.setVisible(False)
        status = result.get('status', '')
        pages  = result.get('pages_processed', 0)
        assets = result.get('assets_downloaded', 0)
        failed = result.get('failed', [])
        out    = result.get('output_dir', '')

        if result.get('cancelled'):
            self.clone_status_lbl.setText(f"Cancelled — {pages} page(s) done")
            self.clone_log.append_warning(
                f"Clone cancelled — {pages} page(s), {assets} asset(s) saved"
            )
            if out:
                self._clone_output_dir = out
                self.btn_clone_open.setEnabled(True)
        elif 'Success' in status or pages > 0:
            self.clone_status_lbl.setText(f"Done — {pages} page(s), {assets} asset(s)")
            self.clone_log.append_success(
                f"Done — {pages} page(s), {assets} asset(s) downloaded"
            )
            if failed:
                self.clone_log.append_warning(
                    f"{len(failed)} asset(s) failed to download"
                )
            if out:
                self.clone_log.append_info(f"Output folder: {out}")
                self._clone_output_dir = out
                self.btn_clone_open.setEnabled(True)
        else:
            self.clone_status_lbl.setText("Failed")
            self.clone_log.append_error(f"Status: {status}")
            if failed:
                for f in failed[:10]:
                    self.clone_log.append_warning(f"  failed: {f}")

    def _open_clone_output(self):
        d = getattr(self, '_clone_output_dir', None)
        if d and Path(d).exists():
            try:
                os.startfile(d)
            except Exception:
                pass

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

    def _render_palette(self, data: dict):
        colors = data.get('colors', [])
        fonts = data.get('fonts', [])

        if colors:
            rows = []
            for c in colors:
                ctype = c.get('type', '')
                val = c.get('value', '')
                if ctype == 'hex':
                    bg = val
                    display = f'<span style="color:#d4d4d4;">{val}</span>'
                elif ctype == 'rgb':
                    bg = c.get('hex', '#888888')
                    display = (
                        f'<span style="color:#d4d4d4;">{val}</span>'
                        f'<span style="color:#555; font-size:10px;">&nbsp;&nbsp;&#8801;&nbsp;{bg}</span>'
                    )
                else:
                    bg = '#666666'
                    display = f'<span style="color:#d4d4d4;">{val}</span>'

                rows.append(
                    f'<tr>'
                    f'<td style="padding:3px 6px;">'
                    f'<span style="background-color:{bg}; padding:4px 14px; '
                    f'font-size:1px; color:{bg};">&nbsp;</span>'
                    f'</td>'
                    f'<td style="padding:3px 10px; font-family:Consolas,monospace; font-size:11px;">'
                    f'{display}</td>'
                    f'<td style="padding:3px 4px; color:#555; font-size:10px;">[{ctype}]</td>'
                    f'</tr>'
                )
            colors_html = (
                '<table border="0" cellspacing="1" cellpadding="1" '
                'style="font-family:Consolas,monospace;">'
                + ''.join(rows)
                + '</table>'
            )
        else:
            colors_html = (
                '<p style="color:#888; font-style:italic; '
                'font-family:Consolas,monospace; padding:8px;">Цвета не найдены</p>'
            )
        self.design_colors.setHtml(colors_html)

        if fonts:
            items = ''.join(
                f'<p style="margin:4px 0;">'
                f'<span style="color:#4fc3f7; font-size:13px;">&#9670;</span>&nbsp;'
                f'<span style="color:#81c784; font-family:Consolas,monospace; '
                f'font-size:12px;">{font}</span>'
                f'</p>'
                for font in fonts
            )
            fonts_html = f'<div style="padding:4px;">{items}</div>'
        else:
            fonts_html = (
                '<p style="color:#888; font-style:italic; '
                'font-family:Consolas,monospace; padding:8px;">Шрифты не найдены</p>'
            )
        self.design_fonts.setHtml(fonts_html)

    def _design_show_placeholder(self):
        msg = (
            '<p style="color:#666; font-style:italic; '
            'font-family:Consolas,monospace; font-size:11px; padding:12px;">'
            'Захватите сайт или запустите анализ для отображения палитры</p>'
        )
        self.design_colors.setHtml(msg)
        self.design_fonts.setHtml(msg)
        self.design_stats_label.setText("")

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
