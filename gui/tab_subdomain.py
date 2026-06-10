"""Subdomain Scanner tab — passive + brute-force enumeration with a live table.

Mixin folded into MainWindow; uses _start_task and _active_subdomain_scanner.
"""

import csv
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QProgressBar, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.subdomain_scanner import SubdomainScanner
from gui.ui_components import SectionGroupBox, StyledButton
from gui.workers import _SubdomainWorker


class SubdomainTabMixin:
    """Builds and drives the Subdomain Scanner tab."""

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
