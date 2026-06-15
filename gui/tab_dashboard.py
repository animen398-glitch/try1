"""Dashboard tab — registry stats, scan control, activity table and the
deduplicated API-endpoint table with drill-down.

Mixin folded into MainWindow; relies on shared helpers (_set_busy,
_run_async) and dashboard state flags initialised in MainWindow.__init__.
"""

import json

from qtpy.QtCore import Qt
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.config import load_settings
from core.executive_summary import display_cards, load_latest_summary
from core.paths import get_path_manager
from gui import theme
from gui.constants import REGISTRY_DB
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton,
)
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
        ('takeovers',     'Takeovers'),
        ('source_maps',   'Source Maps'),
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
        ('Takeover-кандидаты',   'takeover'),
        ('Source Maps',          'source_map'),
    ]

    # (ключ метрики -> подпись карточки) для Security Overview.
    SECURITY_STATS = [
        ('risk_score',     'Risk score'),
        ('attack_surface', 'Attack Surface'),
        ('secrets',        'Секреты'),
        ('high',           'High'),
        ('medium',         'Medium'),
    ]

    ENDPOINTS_COLUMNS = ["Endpoint", "Count", "Sources", "Patterns"]

    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        self.dash_status = QLabel("Всего записей: 0")
        btn_clear = StyledButton("Очистить вид", style='secondary')
        btn_clear.setToolTip(
            "Очищает таблицы и счётчики в интерфейсе.\n"
            "Данные в registry.db не затрагиваются — «Обновить» вернёт их."
        )
        btn_clear.clicked.connect(self._clear_dashboard)
        btn_purge = StyledButton("Очистить БД…", style='secondary')
        btn_purge.setToolTip(
            "УДАЛЯЕТ все записи из registry.db безвозвратно.\n"
            "Запрашивает подтверждение перед удалением."
        )
        btn_purge.clicked.connect(self._purge_registry)
        btn_update = StyledButton("Обновить", style='secondary')
        btn_update.clicked.connect(self._refresh_dashboard)
        ctrl.addWidget(self.dash_status)
        ctrl.addStretch()
        ctrl.addWidget(btn_clear)
        ctrl.addWidget(btn_purge)
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

        # Security overview — reuses the executive summary of the most recent
        # Full Collection (read-only; no extra scan). Empty until one exists.
        sec_grp = SectionGroupBox("Security Overview (последний Full Collection)")
        sec_v = QVBoxLayout()
        self.sec_risk_label = QLabel("Риск: —")
        self.sec_risk_label.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #888;")
        sec_v.addWidget(self.sec_risk_label)
        # "10-second" headline chip strip — the most important signals, compact
        # and prioritized (core.executive_summary.headline). Wraps on narrow.
        self.sec_headline = QWidget()
        self._sec_headline_layout = FlowLayout(self.sec_headline, spacing=6)
        sec_v.addWidget(self.sec_headline)
        sec_cards = QHBoxLayout()
        self.sec_stats: dict = {}
        for key, title in self.SECURITY_STATS:
            card, value_label = self._make_stat_card(title)
            self.sec_stats[key] = value_label
            sec_cards.addWidget(card)
        sec_v.addLayout(sec_cards)
        self.sec_source = QLabel("")
        self.sec_source.setStyleSheet("color: #888; font-size: 11px;")
        self.sec_source.setWordWrap(True)
        sec_v.addWidget(self.sec_source)
        sec_grp.setLayout(sec_v)
        layout.addWidget(sec_grp)

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
        self.dashboard_table.itemSelectionChanged.connect(self._on_dashboard_row_selected)
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

        # Full content of the selected row — read-only, but selectable and
        # copyable (Ctrl+C), so long endpoints/snippets that don't fit a cell
        # can be read and copied in full.
        detail_grp = SectionGroupBox("Детали выбранной строки (выделяется и копируется)")
        detail_layout = QVBoxLayout()
        self.dash_detail = ResultsDisplay()
        self.dash_detail.setMaximumHeight(150)
        self.dash_detail.setPlaceholderText(
            "Выберите строку в таблице, чтобы увидеть полное содержимое")
        detail_layout.addWidget(self.dash_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # Full records backing each table, so a selection can show untruncated text.
        self._dashboard_records: list = []
        self._endpoints_records: list = []

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
        self._dashboard_records = []
        self._endpoints_records = []
        self.dash_detail.clear()
        for label in self.dash_stats.values():
            label.setText("0")
        self._clear_security()
        self._endpoint_filter = None
        self._update_activity_title()
        self.dash_status.setText("Очищено — БД не затронута")

    def _purge_registry(self):
        """Безвозвратно удалить ВСЕ записи из registry.db — после подтверждения.

        Это деструктивное действие (в отличие от «Очистить вид»), поэтому оно
        всегда проходит через диалог подтверждения с дефолтом «Нет». На «Да»
        очищает БД, затем сбрасывает и вид.
        """
        from core.registry import DataRegistry
        try:
            total = DataRegistry(db_path=str(REGISTRY_DB)).count()
        except Exception:
            total = '?'
        reply = QMessageBox.question(
            self, "Очистить базу данных",
            f"Удалить ВСЕ записи реестра ({total}) из registry.db?\n"
            "Действие необратимо.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            removed = DataRegistry(db_path=str(REGISTRY_DB)).clear()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка",
                                 f"Не удалось очистить БД: {e}")
            return
        self._clear_dashboard()
        self.dash_status.setText(f"БД очищена — удалено записей: {removed}")

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
            # Latest Full Collection verdict (read-only; never fatal).
            security = None
            try:
                settings = load_settings()
                dirs = [settings.get('output_dir'),
                        str(get_path_manager().get_reports_path())]
                security = load_latest_summary(dirs)
            except Exception:
                security = None
            return {'summary': viewer.get_summary(), 'endpoints': endpoints,
                    'security': security}
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

        self._populate_security(result.get('security'))

        # A full refresh resets any drill-down back to the type-filter view.
        self._endpoint_filter = None
        self._update_activity_title()
        self._populate_endpoints_table(result.get('endpoints', []))

        # Populate the table according to the currently selected type filter.
        self._apply_dashboard_filter()

    def _populate_security(self, sec: dict):
        """Fill the Security Overview from a loaded executive summary (or clear
        it when no Full Collection report exists yet). Thin setter — all
        formatting/routing lives in core.executive_summary.display_cards."""
        c = display_cards(sec)
        risk_text = (f"Риск: {c['risk_level']} · {c['risk_100']}/100"
                     if c['available']
                     else "Риск: — (нет отчётов Full Collection)")
        self.sec_risk_label.setText(risk_text)
        # Theme-aware: brighter risk colour on the dark theme (the report keeps
        # core RISK_COLORS via display_cards; here the label is on the tab bg).
        risk_col = theme.risk_color(c['risk_level']) or c['risk_color']
        self.sec_risk_label.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {risk_col};")
        self.sec_stats['risk_score'].setText(c['risk_score'])
        surface_text = c['attack_surface']
        if c['available'] and c.get('attack_surface_band') not in ('—', None):
            surface_text = f"{c['attack_surface']} ({c['attack_surface_band']})"
        self.sec_stats['attack_surface'].setText(surface_text)
        self.sec_stats['secrets'].setText(c['secrets'])
        self.sec_stats['high'].setText(c['high'])
        self.sec_stats['medium'].setText(c['medium'])
        self.sec_source.setText(f"Источник: {c['source']}" if c['source'] else "")
        self._set_security_headline(sec if c['available'] else None)

    def _set_security_headline(self, sec):
        """Rebuild the headline chip strip from a summary (cleared when None)."""
        lay = self._sec_headline_layout
        while lay.count():
            item = lay.takeAt(0)
            w = item.widget() if item else None
            if w is not None:
                w.deleteLater()
        if not sec:
            return
        from core.executive_summary import headline
        chips = headline(sec)['chips'] or [
            {'label': 'Критичной экспозиции не выявлено', 'severity': 'clean'}]
        for c in chips:
            color = theme.severity_color(c['severity']) or '#2e7d32'
            chip = QLabel(str(c['label']))
            chip.setStyleSheet(
                f"background:{color};color:#fff;border-radius:10px;"
                f"padding:2px 9px;font-size:11px;font-weight:bold;")
            lay.addWidget(chip)

    def _clear_security(self):
        self._populate_security(None)

    def _populate_endpoints_table(self, endpoints: list):
        self._endpoints_records = endpoints[:200]
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
        self._show_endpoint_detail(rows[0].row())
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

    def _show_endpoint_detail(self, row: int):
        if not (0 <= row < len(self._endpoints_records)):
            return
        ep = self._endpoints_records[row]
        lines = [
            f"Эндпоинт:   {ep.get('endpoint', '')}",
            f"Вхождений:  {ep.get('count', 0)}",
            f"Источников: {ep.get('source_count', 0)}",
        ]
        if ep.get('sources'):
            lines.append("Источники:\n  " + "\n  ".join(ep['sources']))
        if ep.get('patterns'):
            lines.append("Паттерны:   " + ", ".join(ep['patterns']))
        self.dash_detail.setPlainText("\n".join(lines))

    def _update_activity_title(self):
        if self._endpoint_filter:
            self._activity_grp.setTitle(f"Вхождения эндпоинта: {self._endpoint_filter}")
        else:
            self._activity_grp.setTitle("Записи реестра (data/registry.db)")

    def _on_dashboard_row_selected(self):
        rows = self.dashboard_table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if not (0 <= idx < len(self._dashboard_records)):
            return
        rec = self._dashboard_records[idx]
        lines = [
            f"Тип:        {rec.get('data_type', '')}",
            f"Источник:   {rec.get('source', '')}",
            f"Содержимое: {rec.get('content') or ''}",
        ]
        meta = rec.get('metadata')
        if isinstance(meta, dict):
            ctx = meta.get('context')
            if ctx:
                lines.append(f"Контекст:   {ctx}")
            extra = {k: v for k, v in meta.items() if k != 'context'}
            if extra:
                lines.append("Метаданные: "
                             + json.dumps(extra, ensure_ascii=False))
        self.dash_detail.setPlainText("\n".join(lines))

    def _populate_dashboard_table(self, records: list):
        self._dashboard_records = records
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
