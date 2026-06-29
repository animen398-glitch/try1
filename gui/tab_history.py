"""Operation History tab — lists recorded pipeline operations and metadata.

Mixin folded into MainWindow. Also owns _on_tab_changed, which lazy-loads the
History and Dashboard tabs the first time each is opened.
"""

import html
import json

from qtpy.QtCore import Qt
from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from gui.constants import OPERATIONS_DB
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from utils.operation_registry import OperationRegistry


class HistoryTabMixin:
    """Builds and drives the Operation History tab."""

    HISTORY_COLUMNS = [
        "ID", "Target", "Phase", "Status", "Started At", "Warnings", "Duration (ms)",
    ]

    @staticmethod
    def _history_warning_count(row: dict) -> int:
        metadata = row.get('metadata') if isinstance(row.get('metadata'), dict) else {}
        try:
            return int(metadata.get('warning_count') or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _history_warning_tooltip(row: dict) -> str:
        metadata = row.get('metadata') if isinstance(row.get('metadata'), dict) else {}
        lines = []
        for item in metadata.get('warning_summary') or []:
            if not isinstance(item, dict):
                continue
            stage = item.get('stage') or 'pipeline'
            message = item.get('message') or item.get('error') or 'warning'
            error = item.get('error')
            lines.append(f"{stage}: {message}" + (f" ({error})" if error else ""))
        return "\n".join(lines)

    def _build_history_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        self.history_count = QLabel("Записей: 0")
        btn_clear = StyledButton("Сбросить историю", style='secondary')
        btn_clear.setToolTip("Очищает только таблицу в интерфейсе.\n"
                             "Файлы и operations.db не затрагиваются — "
                             "«Обновить» вернёт записи.")
        btn_clear.clicked.connect(self._clear_history_view)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_history)
        ctrl.addWidget(self.history_count)
        ctrl.addStretch()
        ctrl.addWidget(btn_clear)
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

    def _clear_history_view(self):
        """Очистить только GUI-таблицу истории.

        Файлы и data/operations.db НЕ затрагиваются — это сброс представления.
        Флаг _history_view_cleared не даёт lazy-load перезагрузить таблицу при
        возврате на вкладку; «Обновить» сбрасывает флаг и тянет данные заново.
        """
        self._history_rows = []
        self._history_view_cleared = True
        self.history_table.setRowCount(0)
        self.history_meta.clear()
        self.history_count.setText("Записей: 0 (вид очищен — БД не затронута)")

    def _on_tab_changed(self, index: int):
        widget = self.tabs.widget(index)
        if widget is getattr(self, '_history_widget', None):
            if (not self._history_rows and not self._history_loading
                    and not getattr(self, '_history_view_cleared', False)):
                self._refresh_history()
        elif widget is getattr(self, '_dashboard_widget', None):
            if not self._dashboard_loaded and not self._dashboard_loading:
                self._refresh_dashboard()
        elif widget is getattr(self, '_findings_widget', None):
            if not self._findings_loaded and not self._findings_loading:
                self._refresh_findings()
        elif widget is getattr(self, '_remediation_widget', None):
            if not self._rem_loaded and not self._rem_loading:
                self._refresh_remediation()
        elif widget is getattr(self, '_assets_widget', None):
            if not self._assets_loaded and not self._assets_loading:
                self._refresh_assets()
        elif widget is getattr(self, '_intel_widget', None):
            if not self._intel_loaded and not self._intel_loading:
                self._refresh_intelligence()
        elif widget is getattr(self, '_crit_widget', None):
            if not self._crit_loaded and not self._crit_loading:
                self._refresh_criticality()
        elif widget is getattr(self, '_exp_widget', None):
            if not self._exp_loaded and not self._exp_loading:
                self._refresh_exposure()
        elif widget is getattr(self, '_attack_paths_widget', None):
            if not self._attack_paths_loaded and not self._path_loading:
                self._refresh_attack_paths()
        elif widget is getattr(self, '_accuracy_widget', None):
            if not self._acc_loaded and not self._acc_loading:
                self._refresh_accuracy()
        elif widget is getattr(self, '_technology_risk_widget', None):
            if not self._tr_loaded and not self._tr_loading:
                self._refresh_technology_risk()
        elif widget is getattr(self, '_osint_catalog_widget', None):
            if not self._osint_loaded and not self._osint_loading:
                self._refresh_osint_catalog()
        elif widget is getattr(self, '_missions_widget', None):
            if not getattr(self, '_missions_loaded', False) and not self._missions_loading:
                self._refresh_mission_projects()
        elif widget is getattr(self, '_timeline_widget', None):
            if not self._timeline_loaded and not self._timeline_loading:
                self._refresh_timeline()
        elif widget is getattr(self, '_overview_widget', None):
            if not self._overview_loaded and not self._overview_loading:
                self._refresh_overview()

    def _refresh_history(self):
        if self._history_loading:
            return
        self._history_view_cleared = False   # explicit refresh re-enables loading
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
                self._history_warning_count(row),
                row.get('duration_ms'),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem('' if val is None else str(val))
                if col in (0, 5, 6):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if col == 3:  # Status colouring
                    status = (row.get('status') or '').lower()
                    if status == 'success':
                        item.setForeground(QColor('#2e7d32'))
                    elif status == 'failed':
                        item.setForeground(QColor('#d32f2f'))
                    elif status == 'running':
                        item.setForeground(QColor('#0078d4'))
                    elif status == 'cancelled':
                        item.setForeground(QColor('#ef6c00'))
                if col == 5:
                    tip = self._history_warning_tooltip(row)
                    if tip:
                        item.setToolTip(tip)
                        item.setForeground(QColor('#ef6c00'))
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
        # Raw append() renders HTML, so escape the JSON (it can carry recorded
        # target data with <, > or & that would otherwise corrupt the display).
        self.history_meta.append(
            f'<pre style="color:#d4d4d4;margin:0;">{html.escape(text)}</pre>')
