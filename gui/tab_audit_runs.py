"""Audit Runs tab for the Client-Safe Pentest Workbench.

Thin GUI surface over the pure core audit contract. It reads existing findings,
validates/gates them, renders the run, and exports the deterministic audit JSON.
It does not create a second findings store and does not perform active checks.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import audit_runner
from core.audit_templates import list_templates
from core.audit_workflow import AUDIT_PHASES, audit_run_to_json
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

        ctrl.addWidget(QLabel("Scenario:"))
        self.audit_template = QComboBox()
        self.audit_template.setMinimumWidth(180)
        self.audit_template.addItem("Full (v1)", "")
        for tpl in list_templates():
            self.audit_template.addItem(tpl.get("label", tpl["name"]), tpl["name"])
        ctrl.addWidget(self.audit_template)

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
        self.btn_audit_export_md = StyledButton("Export MD", style="secondary")
        self.btn_audit_export_md.setEnabled(False)
        self.btn_audit_export_md.clicked.connect(self._export_audit_markdown)
        ctrl.addWidget(self.btn_audit_export_md)
        self.btn_audit_export_html = StyledButton("Export HTML", style="secondary")
        self.btn_audit_export_html.setEnabled(False)
        self.btn_audit_export_html.clicked.connect(self._export_audit_html)
        ctrl.addWidget(self.btn_audit_export_html)
        layout.addLayout(ctrl)

        history_row = QHBoxLayout()
        history_row.addWidget(QLabel("Audit history:"))
        self.audit_history = QComboBox()
        self.audit_history.setMinimumWidth(320)
        history_row.addWidget(self.audit_history, stretch=1)
        self.btn_audit_open = StyledButton("Open Run", style="secondary")
        self.btn_audit_open.setEnabled(False)
        self.btn_audit_open.clicked.connect(self._open_selected_audit_run)
        history_row.addWidget(self.btn_audit_open)
        layout.addLayout(history_row)

        compare_row = QHBoxLayout()
        compare_row.addWidget(QLabel("Compare baseline:"))
        self.audit_baseline = QComboBox()
        self.audit_baseline.setMinimumWidth(320)
        compare_row.addWidget(self.audit_baseline, stretch=1)
        self.btn_audit_compare = StyledButton("Compare to current", style="secondary")
        self.btn_audit_compare.setEnabled(False)
        self.btn_audit_compare.clicked.connect(self._compare_audit_runs)
        compare_row.addWidget(self.btn_audit_compare)
        self.btn_audit_compare_export = StyledButton("Export Compare", style="secondary")
        self.btn_audit_compare_export.setEnabled(False)
        self.btn_audit_compare_export.clicked.connect(self._export_audit_compare)
        compare_row.addWidget(self.btn_audit_compare_export)
        layout.addLayout(compare_row)

        roe_grp = SectionGroupBox("Rules of Engagement")
        roe_layout = FlowLayout()
        roe_layout.addWidget(QLabel("Allowed:"))
        self.audit_allowed_domains = QLineEdit()
        self.audit_allowed_domains.setMinimumWidth(220)
        roe_layout.addWidget(self.audit_allowed_domains)
        self.audit_active_enabled = QCheckBox("Active")
        roe_layout.addWidget(self.audit_active_enabled)
        self.audit_passive_only = QCheckBox("Passive only")
        self.audit_passive_only.setChecked(True)
        roe_layout.addWidget(self.audit_passive_only)
        roe_layout.addWidget(QLabel("Rate:"))
        self.audit_rate_limit = QLineEdit()
        self.audit_rate_limit.setPlaceholderText("1 rps")
        self.audit_rate_limit.setMaximumWidth(90)
        roe_layout.addWidget(self.audit_rate_limit)
        self.audit_check_headers = QCheckBox("Headers")
        self.audit_check_cookies = QCheckBox("Cookies")
        self.audit_check_sourcemaps = QCheckBox("Source maps")
        self.audit_check_probe = QCheckBox("Probe")
        for cb in (
            self.audit_check_headers,
            self.audit_check_cookies,
            self.audit_check_sourcemaps,
            self.audit_check_probe,
        ):
            roe_layout.addWidget(cb)
        roe_grp.setLayout(roe_layout)
        layout.addWidget(roe_grp)

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
        self._audit_compare: Dict[str, Any] = {}
        self._audit_rows: List[Dict[str, Any]] = []
        self._audit_loading = False
        self._audit_running = False
        self._audit_history_loading = False
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
            self._populate_audit_history([])
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
        if not self.audit_allowed_domains.text().strip():
            self.audit_allowed_domains.setText(str(project))
        self._refresh_audit_history(project)

    def _refresh_audit_history(self, project: str):
        if self._audit_history_loading:
            return
        self._audit_history_loading = True
        self._run_async(
            lambda p=project: self._query_audit_history(p),
            self._on_audit_history_loaded,
        )

    @staticmethod
    def _query_audit_history(project: str) -> dict:
        try:
            from core.audit_store import AuditRunStore
            return {"project": project, "runs": AuditRunStore().list_runs(project)}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_audit_history_loaded(self, result: dict):
        self._audit_history_loading = False
        if result.get("error"):
            self.audit_status.setText(f"History load error: {result['error']}")
            self._populate_audit_history([])
            return
        self._populate_audit_history(result.get("runs") or [])

    def _populate_audit_history(self, runs: List[Dict[str, Any]]):
        current = self.audit_history.currentData()
        self.audit_history.blockSignals(True)
        self.audit_history.clear()
        for row in runs:
            self.audit_history.addItem(
                f"{row.get('updated_at', '')}  {row.get('id', '')}  {row.get('status', '')}",
                row.get("id"),
            )
        idx = self.audit_history.findData(current)
        self.audit_history.setCurrentIndex(idx if idx >= 0 else 0)
        self.audit_history.blockSignals(False)
        self.btn_audit_open.setEnabled(self.audit_history.count() > 0)

        baseline_current = self.audit_baseline.currentData()
        self.audit_baseline.blockSignals(True)
        self.audit_baseline.clear()
        for row in runs:
            self.audit_baseline.addItem(
                f"{row.get('updated_at', '')}  {row.get('id', '')}  {row.get('status', '')}",
                row.get("id"),
            )
        b_idx = self.audit_baseline.findData(baseline_current)
        self.audit_baseline.setCurrentIndex(b_idx if b_idx >= 0 else 0)
        self.audit_baseline.blockSignals(False)
        self._update_compare_enabled()

    def _update_compare_enabled(self):
        has_baseline = self.audit_baseline.count() > 0
        has_current = bool(self._audit_run.get("run_id"))
        self.btn_audit_compare.setEnabled(has_baseline and has_current)

    def _start_audit_run(self):
        project = self.audit_project.currentData()
        if not project:
            self.audit_status.setText("Select a project first")
            return
        if self._audit_running:
            return
        self._audit_running = True
        self.btn_audit_start.setEnabled(False)
        self._set_audit_export_enabled(False)
        self._set_busy(True)
        self.audit_status.setText("Running client-safe audit workflow...")
        run_id = self._new_audit_run_id(project)
        roe = self._current_audit_roe()
        checks = self._selected_safe_checks()
        template = self.audit_template.currentData() or None
        self._run_async(
            lambda p=project, rid=run_id, r=roe, c=checks, t=template: self._query_audit_run(
                p, run_id=rid, roe=r, checks=c, template=t
            ),
            self._on_audit_run_done,
        )

    @staticmethod
    def _new_audit_run_id(project: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in str(project))
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"audit-{safe}-{stamp}"

    @staticmethod
    def _query_audit_run(
        project: str,
        *,
        run_id: str | None = None,
        roe: Dict[str, Any] | None = None,
        checks: List[str] | None = None,
        template: str | None = None,
    ) -> dict:
        # Thin wrapper over the shared core orchestrator (core.audit_runner),
        # which is also used by the Mission Center runner — one implementation.
        try:
            return audit_runner.build_audit_run(
                project, run_id=run_id, roe=roe, checks=checks, template=template
            )
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    @staticmethod
    def _target_from_roe(project: str, roe: Dict[str, Any]) -> str:
        return audit_runner.target_from_roe(project, roe)

    @staticmethod
    def _load_audit_run(run_id: str) -> dict:
        try:
            from core.audit_store import AuditRunStore
            row = AuditRunStore().get_run(run_id)
            if row is None:
                return {"error": f"audit run not found: {run_id}"}
            run = row.get("payload") or {}
            return {"run": run, "rows": audit_runner.rows_from_run(run)}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    @staticmethod
    def _rows_from_run(run: Dict[str, Any]) -> List[Dict[str, Any]]:
        return audit_runner.rows_from_run(run)

    @staticmethod
    def _build_audit_rows(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return audit_runner.build_audit_rows(findings)

    @staticmethod
    def _audit_candidate(finding: Dict[str, Any]) -> Dict[str, Any]:
        return audit_runner.audit_candidate(finding)

    @staticmethod
    def _rollup(rows: List[Dict[str, Any]]) -> Dict[str, int]:
        return audit_runner.rollup(rows)

    def _current_audit_roe(self) -> Dict[str, Any]:
        allowed = [
            item.strip()
            for item in self.audit_allowed_domains.text().split(",")
            if item.strip()
        ]
        return {
            "profile": "client_safe",
            "allowed_domains": allowed,
            "active_scan_enabled": self.audit_active_enabled.isChecked(),
            "passive_only": self.audit_passive_only.isChecked(),
            "rate_limit": self.audit_rate_limit.text().strip() or None,
        }

    def _selected_safe_checks(self) -> List[str]:
        checks = []
        if self.audit_check_headers.isChecked():
            checks.append("headers_check")
        if self.audit_check_cookies.isChecked():
            checks.append("cookie_flags_check")
        if self.audit_check_sourcemaps.isChecked():
            checks.append("source_map_detection")
        if self.audit_check_probe.isChecked():
            checks.append("non_destructive_endpoint_probe")
        return checks

    def _on_audit_run_done(self, result: dict):
        self._audit_running = False
        self.btn_audit_start.setEnabled(True)
        self._set_busy(False)
        if result.get("error"):
            self._audit_run = {}
            self._audit_rows = []
            self._populate_audit_run({}, [])
            self.audit_status.setText(f"Audit run error: {result['error']}")
            self._set_audit_export_enabled(False)
            return
        self._audit_run = result.get("run") or {}
        self._audit_rows = result.get("rows") or []
        self._populate_audit_run(self._audit_run, self._audit_rows)
        self.audit_status.setText(
            f"Audit run completed: {len(self._audit_rows)} finding(s)"
        )
        self._set_audit_export_enabled(True)
        self._update_compare_enabled()
        project = result.get("project") or self.audit_project.currentData()
        if project:
            self._refresh_audit_history(project)

    def _open_selected_audit_run(self):
        run_id = self.audit_history.currentData()
        if not run_id:
            self.audit_status.setText("Select an audit run first")
            return
        self._set_busy(True)
        self._run_async(lambda rid=run_id: self._load_audit_run(rid), self._on_audit_run_opened)

    def _on_audit_run_opened(self, result: dict):
        self._set_busy(False)
        if result.get("error"):
            self.audit_status.setText(f"Open error: {result['error']}")
            return
        self._audit_run = result.get("run") or {}
        self._audit_rows = result.get("rows") or []
        self._populate_audit_run(self._audit_run, self._audit_rows)
        self.audit_status.setText(f"Opened audit run: {self._audit_run.get('run_id', '')}")
        self._set_audit_export_enabled(True)
        self._update_compare_enabled()

    def _compare_audit_runs(self):
        candidate_id = str(self._audit_run.get("run_id") or "")
        baseline_id = self.audit_baseline.currentData()
        if not candidate_id or not baseline_id:
            self.audit_status.setText("Select a baseline and run/open a candidate first")
            return
        if baseline_id == candidate_id:
            self.audit_status.setText("Baseline and candidate are the same run")
            return
        self._set_busy(True)
        self._run_async(
            lambda b=baseline_id, c=candidate_id: self._query_audit_compare(b, c),
            self._on_audit_compare_done,
        )

    @staticmethod
    def _query_audit_compare(baseline_id: str, candidate_id: str) -> dict:
        try:
            from core.audit_store import AuditRunStore
            from core.audit_compare import compare_stored, record_comparison
            store = AuditRunStore()
            diff = compare_stored(store, baseline_id, candidate_id)
            # Deliberate user action → log a 'compared' event for the audit trail.
            record_comparison(store, diff)
            return {"diff": diff}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_audit_compare_done(self, result: dict):
        self._set_busy(False)
        if result.get("error"):
            self.audit_status.setText(f"Compare error: {result['error']}")
            return
        diff = result.get("diff") or {}
        self._audit_compare = diff
        summary = diff.get("summary") or {}
        gate = diff.get("gate") or {}
        gate_state = "PASS" if gate.get("passed") else "FAIL"
        self.audit_status.setText(
            "Compare {cand} vs {base}: "
            "new={new} resolved={resolved} regressed={regressed} "
            "improved={improved} | gate={gate}{inc}".format(
                cand=diff.get("candidate_run_id", ""),
                base=diff.get("baseline_run_id", ""),
                new=summary.get("new", 0),
                resolved=summary.get("resolved", 0),
                regressed=summary.get("regressed", 0),
                improved=summary.get("improved", 0),
                gate=gate_state,
                inc=" (inconclusive)" if diff.get("inconclusive") else "",
            )
        )
        try:
            from core.audit_report import render_compare_markdown
            self.audit_detail.setPlainText(render_compare_markdown(diff))
        except Exception:  # noqa: BLE001
            pass
        self.btn_audit_compare_export.setEnabled(True)

    def _export_audit_compare(self):
        if not self._audit_compare:
            self.audit_status.setText("Nothing to export")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Compare JSON", "audit_compare.json", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            from core.audit_report import render_compare_json
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_compare_json(self._audit_compare))
        except Exception as e:  # noqa: BLE001
            self.audit_status.setText(f"Export failed: {e}")
            return
        self.audit_status.setText(f"Exported audit compare: {path}")

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

    @staticmethod
    def _audit_markdown_payload(run: dict) -> str:
        from core.audit_report import render_markdown
        return render_markdown(run or {})

    @staticmethod
    def _audit_html_payload(run: dict) -> str:
        from core.audit_report import render_html
        return render_html(run or {})

    def _set_audit_export_enabled(self, enabled: bool):
        self.btn_audit_export.setEnabled(enabled)
        self.btn_audit_export_md.setEnabled(enabled)
        self.btn_audit_export_html.setEnabled(enabled)

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

    def _export_audit_markdown(self):
        self._export_audit_report("Export Audit Markdown", "audit_run.md", "Markdown Files (*.md)", self._audit_markdown_payload)

    def _export_audit_html(self):
        self._export_audit_report("Export Audit HTML", "audit_run.html", "HTML Files (*.html)", self._audit_html_payload)

    def _export_audit_report(self, title: str, default_name: str, file_filter: str, renderer):
        if not self._audit_run:
            self.audit_status.setText("Nothing to export")
            return
        path, _ = QFileDialog.getSaveFileName(self, title, default_name, file_filter)
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(renderer(self._audit_run))
        except Exception as e:  # noqa: BLE001
            self.audit_status.setText(f"Export failed: {e}")
            return
        self.audit_status.setText(f"Exported audit report: {path}")
