"""Security Audit tab — native-Python secret + source-map scanner.

Fetches a target page and its JavaScript (via core.security_auditor) and lists
leaked credentials and exposed source maps. Mixin folded into MainWindow; uses
shared helpers (_set_busy, _run_async, _save_target, self.settings).
"""

import threading

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.security_auditor import SecurityAuditor
from gui.ui_components import SectionGroupBox, StyledButton
from gui.workers import _SecurityWorker


class SecurityAuditTabMixin:
    """Builds and drives the Security Audit tab."""

    SECRET_COLUMNS = ["Type", "Preview", "Format", "Source"]
    SOURCEMAP_COLUMNS = ["Source Map", "Sources", "Content", "Secrets"]

    def _build_security_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Цель аудита")
        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.security_url = QLineEdit()
        self.security_url.setPlaceholderText("https://example.com")
        self.security_url.returnPressed.connect(self._run_security_audit)
        self.btn_security_scan = StyledButton("Run Audit")
        self.btn_security_scan.clicked.connect(self._run_security_audit)
        self.btn_security_stop = StyledButton("Остановить", style='secondary')
        self.btn_security_stop.setEnabled(False)
        self.btn_security_stop.clicked.connect(self._stop_security_audit)
        row.addWidget(self.security_url)
        row.addWidget(self.btn_security_scan)
        row.addWidget(self.btn_security_stop)
        grp.setLayout(row)
        layout.addWidget(grp)

        self.security_status = QLabel("Ready")
        self.security_status.setStyleSheet(
            "color:#4fc3f7; font-family:Consolas; font-size:12px; padding:2px 0;"
        )
        layout.addWidget(self.security_status)

        sec_grp = SectionGroupBox("Leaked Secrets")
        sec_layout = QVBoxLayout()
        self.security_table = self._make_table(self.SECRET_COLUMNS, stretch_col=3)
        sec_layout.addWidget(self.security_table)
        sec_grp.setLayout(sec_layout)
        layout.addWidget(sec_grp, stretch=2)

        map_grp = SectionGroupBox("Exposed Source Maps")
        map_layout = QVBoxLayout()
        self.security_map_table = self._make_table(self.SOURCEMAP_COLUMNS, stretch_col=0)
        map_layout.addWidget(self.security_map_table)
        map_grp.setLayout(map_layout)
        layout.addWidget(map_grp, stretch=1)
        return w

    @staticmethod
    def _make_table(columns: list, stretch_col: int) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        hdr = table.horizontalHeader()
        for col in range(len(columns)):
            hdr.setSectionResizeMode(
                col, QHeaderView.Stretch if col == stretch_col
                else QHeaderView.ResizeToContents)
        return table

    @staticmethod
    def _security_registry():
        """A DataRegistry for recording exposed source maps, or None on failure.
        Each add_record opens its own SQLite connection, so handing this to the
        worker thread is safe."""
        try:
            from core.registry import DataRegistry
            return DataRegistry()
        except Exception:
            return None

    def _run_security_audit(self):
        url = self.security_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return
        self.security_table.setRowCount(0)
        self.security_map_table.setRowCount(0)
        self.security_status.setText(f"Аудит: {url} …")
        self.btn_security_scan.setEnabled(False)
        self.btn_security_stop.setEnabled(True)
        self._set_busy(True)

        auditor = SecurityAuditor(
            profile=self.settings.get('user_agent_profile', 'chrome_windows'),
            data_registry=self._security_registry(),
        )
        # Cooperative cancellation: the Stop button sets this event, which the
        # auditor checks between scripts (thread-safe — set from the GUI thread).
        self._security_cancel = threading.Event()
        auditor.set_cancel_event(self._security_cancel)

        worker = _SecurityWorker(auditor, url)
        self._start_task(
            worker,
            on_finished=self._on_security_done,
            on_error=lambda e: (self._reset_security_buttons(),
                                self._set_busy(False),
                                self.security_status.setText(f"Ошибка: {e}")),
            signals=[(worker.log_message, self._on_security_progress)],
        )

    def _on_security_progress(self, msg: str):
        # The auditor logs '[SecurityAudit] …' lines; show them in the status.
        self.security_status.setText(msg.replace('[SecurityAudit] ', '').strip())

    def _stop_security_audit(self):
        if getattr(self, '_security_cancel', None):
            self._security_cancel.set()
            self.security_status.setText("Останавливаю аудит…")
        self.btn_security_stop.setEnabled(False)

    def _reset_security_buttons(self):
        self.btn_security_scan.setEnabled(True)
        self.btn_security_stop.setEnabled(False)

    def _on_security_done(self, result: dict):
        self._set_busy(False)
        self._reset_security_buttons()
        cancelled = getattr(self, '_security_cancel', None) and \
            self._security_cancel.is_set()

        if result.get('status') != 'Success':
            self.security_status.setText(f"Ошибка: {result.get('error', 'unknown')}")
            return

        self._populate_secret_table(result.get('secrets', []))
        self._populate_sourcemap_table(result.get('source_maps', []))

        s = result.get('summary', {})
        prefix = "⛔ Остановлено — " if cancelled else ""
        gql = s.get('graphql', 0)
        gql_part = ''
        if gql:
            intro = s.get('graphql_introspection', 0)
            gql_part = (f"  |  GraphQL: {gql}"
                        + (f" (introspection: {intro})" if intro else ""))
        valid_fmt = s.get('secrets_valid_format', 0)
        self.security_status.setText(
            f"{prefix}Секретов: {s.get('secrets', 0)} "
            f"(формат ок: {valid_fmt})  |  "
            f"эндпоинтов: {s.get('endpoints', 0)}  |  "
            f"source maps: {s.get('source_maps', 0)} "
            f"(с исходниками: {s.get('maps_with_content', 0)})  |  "
            f"JS просканировано: {s.get('scanned_scripts', 0)}"
            f"{gql_part}"
        )
        self._save_target(self.security_url.text().strip())

    # Offline format-validation status → short label + colour for the table.
    _FORMAT_DISPLAY = {
        'valid_format':   ('✓ формат', '#66bb6a'),
        'invalid_format': ('✗ формат', '#bdbdbd'),
        'unverifiable':   ('—', '#9e9e9e'),
    }

    def _populate_secret_table(self, secrets: list):
        self.security_table.setRowCount(0)
        for finding in secrets:
            r = self.security_table.rowCount()
            self.security_table.insertRow(r)
            status = (finding.get('validation') or {}).get('status', 'unverifiable')
            fmt_label, fmt_color = self._FORMAT_DISPLAY.get(
                status, ('—', '#9e9e9e'))
            values = [
                finding.get('type', ''),
                finding.get('preview', ''),
                fmt_label,
                finding.get('source', ''),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 0:
                    item.setForeground(QColor('#e57373'))  # secret type — red
                elif col == 2:
                    item.setForeground(QColor(fmt_color))
                    reason = (finding.get('validation') or {}).get('reason', '')
                    if reason:
                        item.setToolTip(reason)
                self.security_table.setItem(r, col, item)

    def _populate_sourcemap_table(self, maps: list):
        self.security_map_table.setRowCount(0)
        for m in maps:
            r = self.security_map_table.rowCount()
            self.security_map_table.insertRow(r)
            values = [
                m.get('url', ''),
                str(m.get('sources', 0)),
                "✓" if m.get('has_content') else "✗",
                str(m.get('secrets', 0)),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col in (1, 2, 3):
                    item.setTextAlignment(Qt.AlignCenter)
                if col == 2:
                    item.setForeground(
                        QColor('#e57373') if val == "✓" else QColor('#81c784'))
                if col == 3 and m.get('secrets', 0):
                    item.setForeground(QColor('#e57373'))
                self.security_map_table.setItem(r, col, item)
