"""IaC Config tab - local cloud/container config scanner (EPIC NEXT F7 GUI tail).

The core scanner already exists in ``core.iac_scanner`` and is deliberately
local/offline: Dockerfile, docker-compose, Kubernetes, CloudFormation and
Terraform files are parsed from disk into raw findings + container-image
technologies. This tab is the human ad-hoc surface for that engine. It does not
write to the project lifecycle by itself; Full Collection owns lifecycle folding
through its opt-in ``iac`` phase.
"""

import json

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from gui import theme
from gui.ui_components import FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton


class IacTabMixin:
    """Builds and drives the local IaC / container config scan tab."""

    IAC_FINDING_COLUMNS = ["Severity", "Rule", "Title", "Location"]
    IAC_TECH_COLUMNS = ["Image", "Tag"]
    IAC_ROLLUP = [
        ('files', 'Files'),
        ('findings', 'Findings'),
        ('technologies', 'Images'),
        ('skipped_yaml', 'YAML skipped'),
    ]

    def _build_iac_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Path:"))
        self.iac_path = QLineEdit()
        self.iac_path.setPlaceholderText("Select a repo folder, Dockerfile, Terraform file, or manifest")
        ctrl.addWidget(self.iac_path, stretch=1)

        btn_browse = StyledButton("Browse...", style='secondary')
        btn_browse.clicked.connect(self._browse_iac_path)
        ctrl.addWidget(btn_browse)

        self.btn_iac_scan = StyledButton("Scan IaC")
        self.btn_iac_scan.clicked.connect(self._run_iac_scan)
        ctrl.addWidget(self.btn_iac_scan)

        self.btn_iac_export = StyledButton("Export JSON", style='secondary')
        self.btn_iac_export.setEnabled(False)
        self.btn_iac_export.clicked.connect(self._export_iac_json)
        ctrl.addWidget(self.btn_iac_export)
        layout.addLayout(ctrl)

        rollup_row = FlowLayout()
        self.iac_rollup: dict = {}
        for key, title in self.IAC_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.iac_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        self.iac_status = QLabel("Ready - local/offline scan, no cloud API calls")
        layout.addWidget(self.iac_status)

        findings_grp = SectionGroupBox("IaC findings")
        findings_layout = QVBoxLayout()
        self.iac_findings = QTableWidget(0, len(self.IAC_FINDING_COLUMNS))
        self.iac_findings.setHorizontalHeaderLabels(self.IAC_FINDING_COLUMNS)
        self.iac_findings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.iac_findings.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.iac_findings.setSelectionMode(QAbstractItemView.SingleSelection)
        self.iac_findings.verticalHeader().setVisible(False)
        self.iac_findings.setAlternatingRowColors(True)
        f_header = self.iac_findings.horizontalHeader()
        f_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        f_header.setSectionResizeMode(2, QHeaderView.Stretch)
        self.iac_findings.itemSelectionChanged.connect(self._on_iac_finding_selected)
        findings_layout.addWidget(self.iac_findings)
        findings_grp.setLayout(findings_layout)
        layout.addWidget(findings_grp, stretch=2)

        tech_grp = SectionGroupBox("Container images")
        tech_layout = QVBoxLayout()
        self.iac_technologies = QTableWidget(0, len(self.IAC_TECH_COLUMNS))
        self.iac_technologies.setHorizontalHeaderLabels(self.IAC_TECH_COLUMNS)
        self.iac_technologies.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.iac_technologies.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.iac_technologies.verticalHeader().setVisible(False)
        t_header = self.iac_technologies.horizontalHeader()
        t_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        t_header.setSectionResizeMode(0, QHeaderView.Stretch)
        tech_layout.addWidget(self.iac_technologies)
        tech_grp.setLayout(tech_layout)
        layout.addWidget(tech_grp, stretch=1)

        detail_grp = SectionGroupBox("Selected finding detail")
        detail_layout = QVBoxLayout()
        self.iac_detail = ResultsDisplay()
        self.iac_detail.setMaximumHeight(150)
        self.iac_detail.setPlaceholderText("Select an IaC finding to inspect evidence and remediation context.")
        detail_layout.addWidget(self.iac_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._iac_result = {'findings': [], 'technologies': [], 'summary': {}}
        self._iac_scan_running = False
        self._iac_widget = w
        return w

    def _browse_iac_path(self):
        """Pick a directory first; files can still be typed into the path field."""
        path = QFileDialog.getExistingDirectory(self, "Select IaC/config folder")
        if path:
            self.iac_path.setText(path)

    def _run_iac_scan(self):
        path = self.iac_path.text().strip()
        if not path:
            self.iac_status.setText("Select a file or folder first")
            return
        if self._iac_scan_running:
            return
        self._iac_scan_running = True
        self.btn_iac_scan.setEnabled(False)
        self.btn_iac_export.setEnabled(False)
        self._set_busy(True)
        self.iac_status.setText("Scanning local IaC/config files...")
        self._run_async(lambda p=path: self._query_iac_scan(p), self._on_iac_scan_done)

    @staticmethod
    def _query_iac_scan(path: str) -> dict:
        try:
            from core.iac_scanner import scan_path
            return {'path': path, 'data': scan_path(path)}
        except Exception as e:  # noqa: BLE001 - UI must surface errors, not crash
            return {'path': path, 'error': str(e)}

    def _on_iac_scan_done(self, result: dict):
        self._iac_scan_running = False
        self.btn_iac_scan.setEnabled(True)
        self._set_busy(False)
        if result.get('error'):
            self._iac_result = {}
            self._populate_iac(self._iac_result)
            self.btn_iac_export.setEnabled(False)
            self.iac_status.setText(f"Scan error: {result['error']}")
            return
        data = result.get('data') or {}
        self._iac_result = data
        self._populate_iac(data)
        summary = data.get('summary') or {}
        self.iac_status.setText(
            f"Scanned {summary.get('files', 0)} files - "
            f"{summary.get('findings', 0)} findings - "
            f"{summary.get('technologies', 0)} container images"
        )
        self.btn_iac_export.setEnabled(True)

    def _populate_iac(self, data: dict):
        summary = data.get('summary') or {}
        for key, label in self.iac_rollup.items():
            label.setText(str(summary.get(key, 0)))
        self._populate_iac_findings(data.get('findings') or [])
        self._populate_iac_technologies(data.get('technologies') or [])

    def _populate_iac_findings(self, findings: list):
        self.iac_findings.setRowCount(0)
        for f in findings:
            r = self.iac_findings.rowCount()
            self.iac_findings.insertRow(r)
            severity = str(f.get('severity') or '')
            values = [
                severity,
                f.get('rule_id', ''),
                f.get('title', ''),
                f.get('location', ''),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 0:
                    color = theme.severity_color(severity.lower())
                    if color:
                        item.setForeground(QColor(color))
                self.iac_findings.setItem(r, col, item)
        self.iac_detail.clear()

    def _populate_iac_technologies(self, technologies: list):
        self.iac_technologies.setRowCount(0)
        for tech in technologies:
            r = self.iac_technologies.rowCount()
            self.iac_technologies.insertRow(r)
            self.iac_technologies.setItem(r, 0, QTableWidgetItem(str(tech.get('name', ''))))
            self.iac_technologies.setItem(r, 1, QTableWidgetItem(str(tech.get('version', ''))))

    def _selected_iac_finding(self) -> dict:
        sel = self.iac_findings.selectionModel().selectedRows()
        findings = self._iac_result.get('findings') or []
        if not sel:
            return {}
        idx = sel[0].row()
        return findings[idx] if 0 <= idx < len(findings) else {}

    def _on_iac_finding_selected(self):
        f = self._selected_iac_finding()
        if not f:
            return
        lines = [
            f"Severity: {f.get('severity', '')}",
            f"Rule:     {f.get('rule_id', '')}",
            f"Title:    {f.get('title', '')}",
            f"Location: {f.get('location', '')}",
            "",
            str(f.get('detail') or ''),
        ]
        self.iac_detail.setPlainText("\n".join(lines))

    @staticmethod
    def _iac_json_payload(data: dict) -> str:
        return json.dumps(data or {}, ensure_ascii=False, indent=2, default=str)

    def _export_iac_json(self):
        if not (self._iac_result.get('findings') or self._iac_result.get('technologies')):
            self.iac_status.setText("Nothing to export")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export IaC JSON", "iac_scan.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self._iac_json_payload(self._iac_result))
        except Exception as e:  # noqa: BLE001
            self.iac_status.setText(f"Export failed: {e}")
            return
        self.iac_status.setText(f"Exported IaC result: {path}")
