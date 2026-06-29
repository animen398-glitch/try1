"""Missions tab for the Mission Center (Authorized Pentest Multitool, M3).

Thin GUI surface over the persisted missions (``core.mission_store.MissionStore``)
and the pure mission contract (``core.pentest_mission``). It lists existing
missions, drives their lifecycle along the legal transitions, and links existing
audit runs / findings to a mission. It never creates a second store, never runs
active checks, and never mutates findings — mission creation stays in the core /
store layer. All blocking work runs through the shared task runner.
"""

from __future__ import annotations

from typing import Any, Dict, List

from qtpy.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.pentest_mission import MISSION_TRANSITIONS
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton


class MissionsTabMixin:
    """Builds and drives the Missions tab (view + status-advance + add-links)."""

    MISSION_COLUMNS = [
        "Status",
        "Objective",
        "Template",
        "Links",
        "Updated",
        "Mission ID",
    ]

    def _build_missions_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Project:"))
        self.mission_project = QComboBox()
        self.mission_project.setMinimumWidth(240)
        self.mission_project.currentIndexChanged.connect(
            self._on_mission_project_changed)
        ctrl.addWidget(self.mission_project)
        self.mission_profile = QLabel("Profile: client_safe")
        ctrl.addWidget(self.mission_profile, stretch=1)
        self.btn_mission_refresh = StyledButton("Refresh", style="secondary")
        self.btn_mission_refresh.clicked.connect(self._refresh_mission_projects)
        ctrl.addWidget(self.btn_mission_refresh)
        layout.addLayout(ctrl)

        missions_grp = SectionGroupBox("Missions")
        missions_layout = QVBoxLayout()
        self.mission_table = QTableWidget(0, len(self.MISSION_COLUMNS))
        self.mission_table.setHorizontalHeaderLabels(self.MISSION_COLUMNS)
        self.mission_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.mission_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.mission_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.mission_table.verticalHeader().setVisible(False)
        self.mission_table.setAlternatingRowColors(True)
        m_header = self.mission_table.horizontalHeader()
        m_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        m_header.setSectionResizeMode(1, QHeaderView.Stretch)
        self.mission_table.itemSelectionChanged.connect(self._on_mission_selected)
        missions_layout.addWidget(self.mission_table)
        missions_grp.setLayout(missions_layout)
        layout.addWidget(missions_grp, stretch=2)

        advance_row = QHBoxLayout()
        advance_row.addWidget(QLabel("Advance to:"))
        self.mission_advance_status = QComboBox()
        self.mission_advance_status.setMinimumWidth(160)
        advance_row.addWidget(self.mission_advance_status)
        self.btn_mission_advance = StyledButton("Advance status")
        self.btn_mission_advance.setEnabled(False)
        self.btn_mission_advance.clicked.connect(self._advance_mission)
        advance_row.addWidget(self.btn_mission_advance)
        self.btn_mission_run = StyledButton("Run mission")
        self.btn_mission_run.setEnabled(False)
        self.btn_mission_run.clicked.connect(self._run_mission)
        advance_row.addWidget(self.btn_mission_run)
        advance_row.addStretch(1)
        layout.addLayout(advance_row)

        link_row = QHBoxLayout()
        link_row.addWidget(QLabel("Link run:"))
        self.mission_link_run = QComboBox()
        self.mission_link_run.setMinimumWidth(220)
        link_row.addWidget(self.mission_link_run)
        self.btn_mission_link_run = StyledButton("Link run", style="secondary")
        self.btn_mission_link_run.setEnabled(False)
        self.btn_mission_link_run.clicked.connect(self._link_mission_run)
        link_row.addWidget(self.btn_mission_link_run)
        link_row.addWidget(QLabel("Link finding:"))
        self.mission_link_finding = QComboBox()
        self.mission_link_finding.setMinimumWidth(220)
        link_row.addWidget(self.mission_link_finding)
        self.btn_mission_link_finding = StyledButton("Link finding", style="secondary")
        self.btn_mission_link_finding.setEnabled(False)
        self.btn_mission_link_finding.clicked.connect(self._link_mission_finding)
        link_row.addWidget(self.btn_mission_link_finding)
        link_row.addStretch(1)
        layout.addLayout(link_row)

        detail_grp = SectionGroupBox("Selected mission detail")
        detail_layout = QVBoxLayout()
        self.mission_detail = ResultsDisplay()
        self.mission_detail.setMaximumHeight(200)
        detail_layout.addWidget(self.mission_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp, stretch=1)

        self.mission_status = QLabel("Ready")
        layout.addWidget(self.mission_status)

        self._mission_rows: List[Dict[str, Any]] = []
        self._mission_runs: List[Dict[str, Any]] = []
        self._mission_findings: List[Dict[str, Any]] = []
        self._missions_loading = False
        self._missions_list_loading = False
        self._missions_loaded = False
        self._mission_acting = False
        self._mission_reselect_id = ""
        self._missions_widget = w
        return w

    # ── project list ──────────────────────────────────────────────────────────

    def _refresh_mission_projects(self):
        if self._missions_loading:
            return
        self._missions_loading = True
        self._set_busy(True)
        self._run_async(self._query_mission_projects, self._on_mission_projects_loaded)

    @staticmethod
    def _query_mission_projects() -> dict:
        try:
            from core.mission_store import MissionStore
            projects = sorted({
                str(m.get("project") or "")
                for m in MissionStore().list_missions()
                if m.get("project")
            })
            return {"projects": projects}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_mission_projects_loaded(self, result: dict):
        self._missions_loading = False
        self._missions_loaded = True
        self._set_busy(False)
        if result.get("error"):
            self.mission_status.setText(f"Load error: {result['error']}")
            return
        current = self.mission_project.currentData()
        self.mission_project.blockSignals(True)
        self.mission_project.clear()
        for project in result.get("projects", []):
            self.mission_project.addItem(project, project)
        idx = self.mission_project.findData(current)
        self.mission_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.mission_project.blockSignals(False)
        if self.mission_project.count() == 0:
            self.mission_status.setText("No projects with missions")
            self._populate_missions({"missions": [], "audit_runs": [], "findings": []})
            return
        self._on_mission_project_changed()

    def _on_mission_project_changed(self, *args):
        project = self.mission_project.currentData()
        if not project:
            return
        self._refresh_missions(project)

    # ── missions for a project ─────────────────────────────────────────────────

    def _refresh_missions(self, project: str):
        if self._missions_list_loading:
            return
        self._missions_list_loading = True
        self._run_async(
            lambda p=project: self._query_missions(p),
            self._on_missions_loaded,
        )

    @staticmethod
    def _query_missions(project: str) -> dict:
        try:
            from core.mission_store import MissionStore
            missions = MissionStore().list_missions(project)
            runs: List[Dict[str, Any]] = []
            findings: List[Dict[str, Any]] = []
            try:
                from core.audit_store import AuditRunStore
                runs = AuditRunStore().list_runs(project)
            except Exception:  # noqa: BLE001 - link sources are best-effort
                runs = []
            try:
                from core.findings_store import FindingsStore
                findings = FindingsStore().active_findings(project)
            except Exception:  # noqa: BLE001 - link sources are best-effort
                findings = []
            return {"project": project, "missions": missions,
                    "audit_runs": runs, "findings": findings}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_missions_loaded(self, result: dict):
        self._missions_list_loading = False
        if result.get("error"):
            self.mission_status.setText(f"Missions load error: {result['error']}")
            self._populate_missions({"missions": [], "audit_runs": [], "findings": []})
            return
        self._populate_missions(result)
        count = len(result.get("missions") or [])
        self.mission_status.setText(f"{count} mission(s)")

    def _populate_missions(self, result: dict):
        self._mission_rows = list(result.get("missions") or [])
        self._mission_runs = list(result.get("audit_runs") or [])
        self._mission_findings = list(result.get("findings") or [])

        self.mission_table.setRowCount(0)
        for mission in self._mission_rows:
            payload = mission.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            row = self.mission_table.rowCount()
            self.mission_table.insertRow(row)
            n_runs = len(payload.get("linked_audit_run_ids") or [])
            n_findings = len(payload.get("linked_finding_ids") or [])
            values = [
                str(mission.get("status") or ""),
                str(payload.get("objective") or ""),
                str(payload.get("template") or "—"),
                f"{n_runs} run / {n_findings} find",
                str(mission.get("updated_at") or ""),
                str(mission.get("id") or ""),
            ]
            for col, value in enumerate(values):
                self.mission_table.setItem(row, col, QTableWidgetItem(value))

        # repopulate link-source combos before any (re)selection reads them
        self.mission_link_run.clear()
        for run in self._mission_runs:
            rid = str(run.get("id") or "")
            if rid:
                self.mission_link_run.addItem(
                    f"{rid} ({run.get('status', '')})", rid)
        self.mission_link_finding.clear()
        for finding in self._mission_findings:
            fid = str(finding.get("id") or "")
            if fid:
                self.mission_link_finding.addItem(
                    f"{fid}  {finding.get('title', '')}".strip(), fid)

        self.mission_detail.clear()
        self.mission_advance_status.clear()

        # restore the selection across a refresh (e.g. after a mutation); the
        # selectRow signal repopulates the detail/advance combo via the handler.
        reselect = getattr(self, "_mission_reselect_id", "")
        self._mission_reselect_id = ""
        reselected = False
        if reselect:
            for i, mission in enumerate(self._mission_rows):
                if str(mission.get("id") or "") == reselect:
                    self.mission_table.selectRow(i)
                    reselected = True
                    break
        if not reselected:
            self._update_mission_actions()

    # ── selection / detail ─────────────────────────────────────────────────────

    def _selected_mission(self) -> dict:
        sel = self.mission_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        return self._mission_rows[idx] if 0 <= idx < len(self._mission_rows) else {}

    def _on_mission_selected(self):
        mission = self._selected_mission()
        if not mission:
            self.mission_detail.clear()
            self.mission_advance_status.clear()
            self._update_mission_actions()
            return
        payload = mission.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        roe = payload.get("roe") if isinstance(payload.get("roe"), dict) else {}
        lines = [
            f"Mission:   {mission.get('id', '')}",
            f"Objective: {payload.get('objective', '')}",
            f"Status:    {mission.get('status', '')}",
            f"Profile:   {payload.get('profile', '')}",
            f"Template:  {payload.get('template') or '—'}",
            f"Report:    {payload.get('report_orientation', '')}",
            f"Allowed:   {', '.join(payload.get('allowed_actions') or []) or '—'}",
            f"Scope:     {', '.join(roe.get('allowed_domains') or []) or '—'}",
            f"Linked runs:     {', '.join(payload.get('linked_audit_run_ids') or []) or '—'}",
            f"Linked findings: {', '.join(payload.get('linked_finding_ids') or []) or '—'}",
        ]
        self.mission_detail.setPlainText("\n".join(lines))

        status = str(mission.get("status") or "").strip().lower()
        targets = sorted(MISSION_TRANSITIONS.get(status, frozenset()))
        self.mission_advance_status.clear()
        for target in targets:
            self.mission_advance_status.addItem(target, target)
        self._update_mission_actions()

    def _update_mission_actions(self):
        mission = self._selected_mission()
        has_mission = bool(mission)
        idle = has_mission and not self._mission_acting
        status = str(mission.get("status") or "").strip().lower()
        self.btn_mission_advance.setEnabled(
            idle and self.mission_advance_status.count() > 0)
        self.btn_mission_link_run.setEnabled(
            idle and self.mission_link_run.count() > 0)
        self.btn_mission_link_finding.setEnabled(
            idle and self.mission_link_finding.count() > 0)
        # A mission is executable only from the 'ready' state.
        self.btn_mission_run.setEnabled(idle and status == "ready")

    # ── mutations (advance / link), all via the pure contract + store ──────────

    def _begin_mission_action(self) -> dict:
        mission = self._selected_mission()
        if not mission or self._mission_acting:
            return {}
        payload = mission.get("payload")
        if not isinstance(payload, dict):
            return {}
        self._mission_acting = True
        self._update_mission_actions()
        self._set_busy(True)
        return payload

    def _advance_mission(self):
        payload = self._begin_mission_action()
        if not payload:
            return
        target = self.mission_advance_status.currentData()
        self.mission_status.setText(f"Advancing to {target}...")
        self._run_async(
            lambda p=payload, t=target: self._do_advance_mission(p, t),
            self._on_mission_action_done,
        )

    @staticmethod
    def _do_advance_mission(payload: Dict[str, Any], target: str) -> dict:
        try:
            from core.pentest_mission import advance_mission_status
            from core.mission_store import MissionStore
            updated = advance_mission_status(payload, str(target))
            MissionStore().save_mission(updated)
            return {"ok": f"status → {target}"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _link_mission_run(self):
        payload = self._begin_mission_action()
        if not payload:
            return
        run_id = self.mission_link_run.currentData()
        self.mission_status.setText(f"Linking run {run_id}...")
        self._run_async(
            lambda p=payload, r=run_id: self._do_link_run(p, r),
            self._on_mission_action_done,
        )

    @staticmethod
    def _do_link_run(payload: Dict[str, Any], run_id: str) -> dict:
        try:
            from core.pentest_mission import link_audit_run
            from core.mission_store import MissionStore
            updated = link_audit_run(payload, str(run_id))
            MissionStore().save_mission(updated)
            return {"ok": f"linked run {run_id}"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _link_mission_finding(self):
        payload = self._begin_mission_action()
        if not payload:
            return
        finding_id = self.mission_link_finding.currentData()
        self.mission_status.setText(f"Linking finding {finding_id}...")
        self._run_async(
            lambda p=payload, f=finding_id: self._do_link_finding(p, f),
            self._on_mission_action_done,
        )

    @staticmethod
    def _do_link_finding(payload: Dict[str, Any], finding_id: str) -> dict:
        try:
            from core.pentest_mission import link_finding
            from core.mission_store import MissionStore
            updated = link_finding(payload, str(finding_id))
            MissionStore().save_mission(updated)
            return {"ok": f"linked finding {finding_id}"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _run_mission(self):
        payload = self._begin_mission_action()
        if not payload:
            return
        self.mission_status.setText("Running mission (client-safe audit run)...")
        self._run_async(
            lambda p=payload: self._do_run_mission(p),
            self._on_mission_action_done,
        )

    @staticmethod
    def _do_run_mission(payload: Dict[str, Any]) -> dict:
        try:
            from core.mission_runner import run_mission
            out = run_mission(payload)
            return {"ok": f"mission ran → {out['run_id']} ({out['status']})"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_mission_action_done(self, result: dict):
        self._mission_acting = False
        self._set_busy(False)
        if result.get("error"):
            self.mission_status.setText(f"Action failed: {result['error']}")
            self._update_mission_actions()
            return
        selected_id = str(self._selected_mission().get("id") or "")
        self.mission_status.setText(result.get("ok") or "Done")
        self._mission_reselect_id = selected_id
        project = self.mission_project.currentData()
        if project:
            self._refresh_missions(project)
