import csv
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from PyQt5.QtCore import Qt, QThread
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
from gui.workers import (
    _CaptureWorker, _CloneWorker, _SubdomainWorker, _TaskHandle, _Worker,
)
from gui.constants import (
    LIVE_TEST_OUTPUT, OPERATIONS_DB, REGISTRY_DB, SETTINGS_FILE, TARGETS_FILE,
)
from gui.tab_system import SystemTabMixin
from gui.tab_api import ApiTabMixin
from gui.tab_capture import CaptureTabMixin
from gui.tab_design import DesignTabMixin
from gui.tab_media import ImageTabMixin, VideoTabMixin
from gui.tab_recon import ReconTabMixin
from gui.tab_subdomain import SubdomainTabMixin
from utils.file_compression import FileCompressor
from utils.operation_registry import OperationRegistry
from utils.data_viewer import DataViewer
from utils.task_manager import TaskManager
from utils.exporter import DataExporter
from utils.endpoint_index import EndpointIndex
from utils.site_extractor import SiteExtractor
from utils.system_logger import get_last_logs

class MainWindow(QMainWindow, SystemTabMixin, ApiTabMixin,
                 VideoTabMixin, ImageTabMixin, CaptureTabMixin,
                 DesignTabMixin, ReconTabMixin, SubdomainTabMixin):
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
