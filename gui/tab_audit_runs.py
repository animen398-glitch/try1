"""Audit Runs tab for the Client-Safe Pentest Workbench.

Thin GUI surface over the pure core audit contract. It reads existing findings,
validates/gates them, renders the run, and exports the deterministic audit JSON.
It does not create a second findings store and does not perform active checks.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.audit_workflow import (
    AUDIT_PHASES,
    advance_audit_phase,
    audit_run_to_json,
    create_audit_run,
)
from core.finding_quality import apply_quality_gate
from core.finding_validation import validate_finding
from gui import theme
from gui.ui_components import FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton


class AuditRunsTabMixin:
    """Builds and drives the Audit Runs tab."""

    AUDIT_COLUMNS = [
        "Severity",
        "Validation",
        "Confidence",
        "Quality",
        "Finding",
        "Evidence refs",
    ]
    AUDIT_ROLLUP = [
        ("verified", "Verified"),
        ("rejected", "Rejected"),
        ("needs_review", "Needs review"),
        ("quality_failed", "Gate failed"),
    ]

    def _build_audit_runs_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Project:"))
        self.audit_project = QComboBox()
        self.audit_project.setMinimumWidth(240)
        self.audit_project.currentIndexChanged.connect(self._on_audit_project_changed)
        ctrl.addWidget(self.audit_project)

        self.audit_profile = QLabel("Profile: client_safe")
        ctrl.addWidget(self.audit_profile)
        self.audit_scope = QLabel("Scope: select a project")
        ctrl.addWidget(self.audit_scope, stretch=1)

        self.btn_audit_refresh = StyledButton("Refresh", style="secondary")
        self.btn_audit_refresh.clicked.connect(self._refresh_audit_projects)
        ctrl.addWidget(self.btn_audit_refresh)

        self.btn_audit_start = StyledButton("Start Audit Run")
        self.btn_audit_start.clicked.connect(self._start_audit_run)
        ctrl.addWidget(self.btn_audit_start)

        self.btn_audit_export = StyledButton("Export JSON", style="secondary")
        self.btn_audit_export.setEnabled(False)
        self.btn_audit_export.clicked.connect(self._export_audit_json)
        ctrl.addWidget(self.btn_audit_export)
        layout.addLayout(ctrl)

        progress_row = QHBoxLayout()
        self.audit_status = QLabel("Ready")
        progress_row.addWidget(self.audit_status, stretch=1)
        self.audit_progress = QProgressBar()
        self.audit_progress.setRange(0, len(AUDIT_PHASES))
        self.audit_progress.setValue(0)
        self.audit_progress.setMinimumWidth(240)
        progress_row.addWidget(self.audit_progress)
        layout.addLayout(progress_row)

        rollup_row = FlowLayout()
        self.audit_rollup: dict = {}
        for key, title in self.AUDIT_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.audit_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        phases_grp = SectionGroupBox("Phase progress")
        phases_layout = QVBoxLayout()
        self.audit_phases = QTableWidget(0, 3)
        self.audit_phases.setHorizontalHeaderLabels(["Phase", "Status", "Result"])
        self.audit_phases.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.audit_phases.verticalHeader().setVisible(False)
        p_header = self.audit_phases.horizontalHeader()
        p_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        p_header.setSectionResizeMode(2, QHeaderView.Stretch)
        phases_layout.addWidget(self.audit_phases)
        phases_grp.setLayout(phases_layout)
        layout.addWidget(phases_grp, stretch=1)

        findings_grp = SectionGroupBox("Audit findings")
        findings_layout = QVBoxLayout()
        self.audit_findings = QTableWidget(0, len(self.AUDIT_COLUMNS))
        self.audit_findings.setHorizontalHeaderLabels(self.AUDIT_COLUMNS)
        self.audit_findings.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.audit_findings.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.audit_findings.setSelectionMode(QAbstractItemView.SingleSelection)
        self.audit_findings.verticalHeader().setVisible(False)
        self.audit_findings.setAlternatingRowColors(True)
        f_header = self.audit_findings.horizontalHeader()
        f_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        f_header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.audit_findings.itemSelectionChanged.connect(self._on_audit_finding_selected)
        findings_layout.addWidget(self.audit_findings)
        findings_grp.setLayout(findings_layout)
        layout.addWidget(findings_grp, stretch=2)

        detail_grp = SectionGroupBox("Selected finding detail")
        detail_layout = QVBoxLayout()
        self.audit_detail = ResultsDisplay()
        self.audit_detail.setMaximumHeight(150)
        detail_layout.addWidget(self.audit_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._audit_run: Dict[str, Any] = {}
        self._audit_rows: List[Dict[str, Any]] = []
        self._audit_loading = False
        self._audit_running = False
        self._audit_widget = w
        return w

    def _refresh_audit_projects(self):
        if self._audit_loading:
            return
        self._audit_loading = True
        self._set_busy(True)
        self._run_async(self._query_audit_projects, self._on_audit_projects_loaded)

    @staticmethod
    def _query_audit_projects() -> dict:
        try:
            from core.findings_store import FindingsStore
            return {"projects": FindingsStore().projects()}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_audit_projects_loaded(self, result: dict):
        self._audit_loading = False
        self._set_busy(False)
        if result.get("error"):
            self.audit_status.setText(f"Load error: {result['error']}")
            return
        current = self.audit_project.currentData()
        self.audit_project.blockSignals(True)
        self.audit_project.clear()
        for project in result.get("projects", []):
            self.audit_project.addItem(
                f"{project['project']} ({project['active']}/{project['total']})",
                project["project"],
            )
        idx = self.audit_project.findData(current)
        self.audit_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.audit_project.blockSignals(False)
        if self.audit_project.count() == 0:
            self.audit_status.setText("No projects with findings")
            self.audit_scope.setText("Scope: no project")
            return
        self._on_audit_project_changed()

    def _on_audit_project_changed(self, *args):
        project = self.audit_project.currentData()
        if not project:
            self.audit_scope.setText("Scope: no project")
            return
        self.audit_scope.setText(
            f"Scope: project findings only; active checks require ROE for {project}"
        )

    def _start_audit_run(self):
        project = self.audit_project.currentData()
        if not project:
            self.audit_status.setText("Select a project first")
            return
        if self._audit_running:
            return
        self._audit_running = True
        self.btn_audit_start.setEnabled(False)
        self.btn_audit_export.setEnabled(False)
        self._set_busy(True)
        self.audit_status.setText("Running client-safe audit workflow...")
        self._run_async(lambda p=project: self._query_audit_run(p), self._on_audit_run_done)

    @staticmethod
    def _query_audit_run(project: str) -> dict:
        try:
            from core.findings_store import FindingsStore
            findings = FindingsStore().active_findings(project)
            run = create_audit_run(project)
            rows = AuditRunsTabMixin._build_audit_rows(findings)
            run = advance_audit_phase(
                run,
                "recon_snapshot",
                {"project": project, "active_findings": len(findings)},
            )
            run = advance_audit_phase(
                run,
                "finding_hunt",
                {"findings": [row["finding"] for row in rows]},
            )
            run = advance_audit_phase(
                run,
                "validation",
                {"validated_findings": [row["finding"] for row in rows]},
            )
            run = advance_audit_phase(
                run,
                "risk_business_impact",
                {"quality": AuditRunsTabMixin._rollup(rows)},
            )
            run = advance_audit_phase(
                run,
                "structured_output",
                {"schema": "asa_audit_run", "export": "json"},
            )
            run = advance_audit_phase(
                run,
                "independent_verification",
                {"evidence_refs": sorted({ref for row in rows for ref in row["evidence_refs"]})},
            )
            return {"project": project, "run": audit_run_to_json(run), "rows": rows}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    @staticmethod
    def _build_audit_rows(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows = []
        for finding in findings:
            candidate = AuditRunsTabMixin._audit_candidate(finding)
            evidence = finding.get("evidence") if isinstance(finding, dict) else {}
            validated = validate_finding(candidate, evidence=evidence)
            gated = apply_quality_gate(validated, min_confidence=70)
            rows.append(
                {
                    "source": finding,
                    "finding": gated,
                    "evidence_refs": list(gated.get("evidence_refs") or []),
                }
            )
        rows.sort(key=lambda row: (row["finding"].get("title", ""), row["finding"].get("id", "")))
        return rows

    @staticmethod
    def _audit_candidate(finding: Dict[str, Any]) -> Dict[str, Any]:
        evidence = finding.get("evidence") if isinstance(finding, dict) else {}
        if not isinstance(evidence, dict):
            evidence = {}
        fid = str(finding.get("id") or "")
        evidence_refs = list(evidence.get("evidence_refs") or evidence.get("refs") or [])
        if evidence and not evidence_refs:
            evidence_refs = [f"finding:{fid}:evidence"]
        location = (
            evidence.get("location")
            or evidence.get("url")
            or evidence.get("source")
            or finding.get("location")
            or ""
        )
        asset = evidence.get("asset") or evidence.get("host") or finding.get("project") or ""
        return {
            "id": fid,
            "finding_id": fid,
            "title": finding.get("title", ""),
            "severity": str(finding.get("severity") or "info").lower(),
            "asset": asset,
            "location": location,
            "impact": evidence.get("impact") or finding.get("impact") or "",
            "business_impact": evidence.get("business_impact") or "",
            "remediation": evidence.get("remediation") or finding.get("remediation") or "",
            "reachability": evidence.get("reachability") or evidence.get("context") or "",
            "confidence": int(evidence.get("confidence") or finding.get("confidence") or 70),
            "validation_status": "unverified",
            "evidence_refs": evidence_refs,
        }

    @staticmethod
    def _rollup(rows: List[Dict[str, Any]]) -> Dict[str, int]:
        out = {"verified": 0, "rejected": 0, "needs_review": 0, "quality_failed": 0}
        for row in rows:
            finding = row.get("finding") or {}
            status = finding.get("validation_status")
            if status in out:
                out[status] += 1
            if finding.get("quality_gate") == "failed":
                out["quality_failed"] += 1
        return out

    def _on_audit_run_done(self, result: dict):
        self._audit_running = False
        self.btn_audit_start.setEnabled(True)
        self._set_busy(False)
        if result.get("error"):
            self._audit_run = {}
            self._audit_rows = []
            self._populate_audit_run({}, [])
            self.audit_status.setText(f"Audit run error: {result['error']}")
            self.btn_audit_export.setEnabled(False)
            return
        self._audit_run = result.get("run") or {}
        self._audit_rows = result.get("rows") or []
        self._populate_audit_run(self._audit_run, self._audit_rows)
        self.audit_status.setText(
            f"Audit run completed: {len(self._audit_rows)} finding(s)"
        )
        self.btn_audit_export.setEnabled(True)

    def _populate_audit_run(self, run: dict, rows: List[Dict[str, Any]]):
        phases = run.get("phases") or []
        self.audit_progress.setValue(
            sum(1 for phase in phases if phase.get("status") == "completed")
        )
        self._populate_audit_phases(phases)
        self._populate_audit_findings(rows)
        rollup = self._rollup(rows)
        for key, label in self.audit_rollup.items():
            label.setText(str(rollup.get(key, 0)))

    def _populate_audit_phases(self, phases: list):
        self.audit_phases.setRowCount(0)
        for phase in phases:
            row = self.audit_phases.rowCount()
            self.audit_phases.insertRow(row)
            result = phase.get("result")
            summary = ""
            if isinstance(result, dict):
                summary = ", ".join(f"{k}={v}" for k, v in sorted(result.items())[:3])
            values = [phase.get("name", ""), phase.get("status", ""), summary]
            for col, value in enumerate(values):
                self.audit_phases.setItem(row, col, QTableWidgetItem(str(value)))

    def _populate_audit_findings(self, rows: List[Dict[str, Any]]):
        self.audit_findings.setRowCount(0)
        for record in rows:
            finding = record.get("finding") or {}
            row = self.audit_findings.rowCount()
            self.audit_findings.insertRow(row)
            severity = str(finding.get("severity") or "")
            values = [
                severity,
                finding.get("validation_status", ""),
                str(finding.get("confidence", "")),
                finding.get("quality_gate", ""),
                finding.get("title", ""),
                ", ".join(record.get("evidence_refs") or []),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 0:
                    color = theme.severity_color(severity.lower())
                    if color:
                        item.setForeground(QColor(color))
                elif col == 3 and value == "failed":
                    item.setForeground(QColor(theme.severity_color("high")))
                self.audit_findings.setItem(row, col, item)
        self.audit_detail.clear()

    def _selected_audit_record(self) -> dict:
        sel = self.audit_findings.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        return self._audit_rows[idx] if 0 <= idx < len(self._audit_rows) else {}

    def _on_audit_finding_selected(self):
        record = self._selected_audit_record()
        if not record:
            return
        finding = record.get("finding") or {}
        lines = [
            f"Finding:   {finding.get('title', '')}",
            f"Severity:  {finding.get('severity', '')}",
            f"Status:    {finding.get('validation_status', '')}",
            f"Confidence:{finding.get('confidence', '')}",
            f"Quality:   {finding.get('quality_gate', '')}",
            f"Evidence:  {', '.join(record.get('evidence_refs') or [])}",
            f"Asset:     {finding.get('asset', '')}",
            f"Location:  {finding.get('location', '')}",
        ]
        reasons = finding.get("quality_reasons") or finding.get("validation_reasons") or []
        if reasons:
            lines.append(f"Reasons:   {', '.join(reasons)}")
        self.audit_detail.setPlainText("\n".join(lines))

    @staticmethod
    def _audit_json_payload(run: dict) -> str:
        return json.dumps(audit_run_to_json(run or {}), ensure_ascii=False, indent=2, sort_keys=True)

    def _export_audit_json(self):
        if not self._audit_run:
            self.audit_status.setText("Nothing to export")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Run JSON", "audit_run.json", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._audit_json_payload(self._audit_run))
        except Exception as e:  # noqa: BLE001
            self.audit_status.setText(f"Export failed: {e}")
            return
        self.audit_status.setText(f"Exported audit run: {path}")
