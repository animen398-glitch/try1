"""Dashboard tab — registry stats, scan control, activity table and the
deduplicated API-endpoint table with drill-down.

Mixin folded into MainWindow; relies on shared helpers (_set_busy,
_run_async) and dashboard state flags initialised in MainWindow.__init__.
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from gui.constants import REGISTRY_DB
from gui.ui_components import SectionGroupBox, StyledButton
from utils.data_viewer import DataViewer
from utils.endpoint_index import EndpointIndex
from utils.site_extractor import SiteExtractor


class DashboardTabMixin:
    """Builds and drives the Dashboard tab."""

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
        btn_clear = StyledButton("Очистить", style='secondary')
        btn_clear.setToolTip(
            "Очищает таблицы и счётчики в интерфейсе.\n"
            "Данные в registry.db не затрагиваются — «Обновить» вернёт их."
        )
        btn_clear.clicked.connect(self._clear_dashboard)
        btn_update = StyledButton("Обновить", style='secondary')
        btn_update.clicked.connect(self._refresh_dashboard)
        ctrl.addWidget(self.dash_status)
        ctrl.addStretch()
        ctrl.addWidget(btn_clear)
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

    def _clear_dashboard(self):
        """Очистить отображение дашборда (таблицы + счётчики), не трогая БД.

        Сбрасывает обе таблицы, счётчики-карточки и любой активный drill-down.
        Реестр registry.db не меняется — «Обновить» вернёт данные. Флаг
        _dashboard_loaded остаётся True, чтобы возврат на вкладку не перезагрузил
        вид автоматически.
        """
        self.dashboard_table.setRowCount(0)
        self.endpoints_table.setRowCount(0)
        for label in self.dash_stats.values():
            label.setText("0")
        self._endpoint_filter = None
        self._update_activity_title()
        self.dash_status.setText("Очищено — БД не затронута")

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
