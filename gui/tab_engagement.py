"""Engagements tab — Engagement & ROE Foundation surface (S4).

Thin GUI surface over the persisted engagements (``core.engagement_store``) and
the pure engagement contract (``core.engagement``). It lists engagements, creates
client-safe ones, drives the lifecycle along the legal transitions, links
existing missions / audit runs / findings (existence-checked via
``core.engagement_links``), prunes stale links, and exports the evidence-first
report. It never creates a second store and never mutates findings/missions/runs.
All blocking work runs through the shared task runner (``_run_async``).
"""

from __future__ import annotations

from typing import Any, Dict, List

from qtpy.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.engagement import ENGAGEMENT_TRANSITIONS
from gui.ui_components import FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton


class EngagementsTabMixin:
    """Builds and drives the Engagements tab (view + create + advance + links)."""

    ENGAGEMENT_COLUMNS = ["Status", "Client", "Links", "Updated", "Engagement ID"]

    def _build_engagement_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Project:"))
        self.engagement_project = QComboBox()
        self.engagement_project.setMinimumWidth(240)
        self.engagement_project.currentIndexChanged.connect(
            self._on_engagement_project_changed)
        ctrl.addWidget(self.engagement_project)
        self.engagement_profile = QLabel("Profile: client_safe")
        ctrl.addWidget(self.engagement_profile, stretch=1)
        self.btn_engagement_refresh = StyledButton("Refresh", style="secondary")
        self.btn_engagement_refresh.clicked.connect(self._refresh_engagement_projects)
        ctrl.addWidget(self.btn_engagement_refresh)
        layout.addLayout(ctrl)

        # ── create panel (client-safe) ──────────────────────────────────────
        create_grp = SectionGroupBox("Create engagement (client-safe)")
        create_layout = FlowLayout()
        create_layout.addWidget(QLabel("Client:"))
        self.engagement_create_client = QLineEdit()
        self.engagement_create_client.setPlaceholderText("client name")
        self.engagement_create_client.setMinimumWidth(150)
        create_layout.addWidget(self.engagement_create_client)
        create_layout.addWidget(QLabel("Project:"))
        self.engagement_create_project = QLineEdit()
        self.engagement_create_project.setPlaceholderText("project / domain")
        self.engagement_create_project.setMinimumWidth(150)
        create_layout.addWidget(self.engagement_create_project)
        create_layout.addWidget(QLabel("Allowed domains:"))
        self.engagement_create_domains = QLineEdit()
        self.engagement_create_domains.setMinimumWidth(150)
        create_layout.addWidget(self.engagement_create_domains)
        self.engagement_create_active = QCheckBox("Active")
        create_layout.addWidget(self.engagement_create_active)
        self.engagement_create_passive = QCheckBox("Passive only")
        self.engagement_create_passive.setChecked(True)
        create_layout.addWidget(self.engagement_create_passive)
        create_layout.addWidget(QLabel("Rate:"))
        self.engagement_create_rate = QLineEdit()
        self.engagement_create_rate.setPlaceholderText("1 rps")
        self.engagement_create_rate.setMaximumWidth(90)
        create_layout.addWidget(self.engagement_create_rate)
        self.engagement_create_accepted = QCheckBox("Authorization accepted")
        create_layout.addWidget(self.engagement_create_accepted)
        create_layout.addWidget(QLabel("Authorized by:"))
        self.engagement_create_authby = QLineEdit()
        self.engagement_create_authby.setMinimumWidth(120)
        create_layout.addWidget(self.engagement_create_authby)
        self.btn_engagement_create = StyledButton("Create engagement")
        self.btn_engagement_create.clicked.connect(self._create_engagement)
        create_layout.addWidget(self.btn_engagement_create)
        create_grp.setLayout(create_layout)
        layout.addWidget(create_grp)

        # ── engagements table ───────────────────────────────────────────────
        grp = SectionGroupBox("Engagements")
        grp_layout = QVBoxLayout()
        self.engagement_table = QTableWidget(0, len(self.ENGAGEMENT_COLUMNS))
        self.engagement_table.setHorizontalHeaderLabels(self.ENGAGEMENT_COLUMNS)
        self.engagement_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.engagement_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.engagement_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.engagement_table.verticalHeader().setVisible(False)
        self.engagement_table.setAlternatingRowColors(True)
        header = self.engagement_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        self.engagement_table.itemSelectionChanged.connect(
            self._on_engagement_selected)
        grp_layout.addWidget(self.engagement_table)
        grp.setLayout(grp_layout)
        layout.addWidget(grp, stretch=2)

        # ── advance row ─────────────────────────────────────────────────────
        advance_row = QHBoxLayout()
        advance_row.addWidget(QLabel("Advance to:"))
        self.engagement_advance_status = QComboBox()
        self.engagement_advance_status.setMinimumWidth(150)
        advance_row.addWidget(self.engagement_advance_status)
        self.btn_engagement_advance = StyledButton("Advance status")
        self.btn_engagement_advance.setEnabled(False)
        self.btn_engagement_advance.clicked.connect(self._advance_engagement)
        advance_row.addWidget(self.btn_engagement_advance)
        self.btn_engagement_prune = StyledButton("Remove stale", style="secondary")
        self.btn_engagement_prune.setEnabled(False)
        self.btn_engagement_prune.clicked.connect(self._prune_engagement_links)
        advance_row.addWidget(self.btn_engagement_prune)
        advance_row.addStretch(1)
        layout.addLayout(advance_row)

        # ── link row (mission / audit run / finding) ────────────────────────
        link_row = QHBoxLayout()
        link_row.addWidget(QLabel("Link mission:"))
        self.engagement_link_mission = QComboBox()
        self.engagement_link_mission.setMinimumWidth(180)
        link_row.addWidget(self.engagement_link_mission)
        self.btn_engagement_link_mission = StyledButton("Link", style="secondary")
        self.btn_engagement_link_mission.setEnabled(False)
        self.btn_engagement_link_mission.clicked.connect(
            lambda: self._link_engagement("mission"))
        link_row.addWidget(self.btn_engagement_link_mission)
        link_row.addWidget(QLabel("run:"))
        self.engagement_link_run = QComboBox()
        self.engagement_link_run.setMinimumWidth(160)
        link_row.addWidget(self.engagement_link_run)
        self.btn_engagement_link_run = StyledButton("Link", style="secondary")
        self.btn_engagement_link_run.setEnabled(False)
        self.btn_engagement_link_run.clicked.connect(
            lambda: self._link_engagement("audit_run"))
        link_row.addWidget(self.btn_engagement_link_run)
        link_row.addWidget(QLabel("finding:"))
        self.engagement_link_finding = QComboBox()
        self.engagement_link_finding.setMinimumWidth(160)
        link_row.addWidget(self.engagement_link_finding)
        self.btn_engagement_link_finding = StyledButton("Link", style="secondary")
        self.btn_engagement_link_finding.setEnabled(False)
        self.btn_engagement_link_finding.clicked.connect(
            lambda: self._link_engagement("finding"))
        link_row.addWidget(self.btn_engagement_link_finding)
        link_row.addStretch(1)
        layout.addLayout(link_row)

        # ── report export row ───────────────────────────────────────────────
        report_row = QHBoxLayout()
        report_row.addWidget(QLabel("Engagement report:"))
        self.btn_engagement_report_json = StyledButton("Export JSON", style="secondary")
        self.btn_engagement_report_json.setEnabled(False)
        self.btn_engagement_report_json.clicked.connect(
            lambda: self._export_engagement_report("json"))
        report_row.addWidget(self.btn_engagement_report_json)
        self.btn_engagement_report_md = StyledButton("Export MD", style="secondary")
        self.btn_engagement_report_md.setEnabled(False)
        self.btn_engagement_report_md.clicked.connect(
            lambda: self._export_engagement_report("md"))
        report_row.addWidget(self.btn_engagement_report_md)
        self.btn_engagement_report_html = StyledButton("Export HTML", style="secondary")
        self.btn_engagement_report_html.setEnabled(False)
        self.btn_engagement_report_html.clicked.connect(
            lambda: self._export_engagement_report("html"))
        report_row.addWidget(self.btn_engagement_report_html)
        report_row.addStretch(1)
        layout.addLayout(report_row)

        detail_grp = SectionGroupBox("Selected engagement detail")
        detail_layout = QVBoxLayout()
        self.engagement_detail = ResultsDisplay()
        self.engagement_detail.setMaximumHeight(200)
        detail_layout.addWidget(self.engagement_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp, stretch=1)

        self.engagement_status = QLabel("Ready")
        layout.addWidget(self.engagement_status)

        self._engagement_rows: List[Dict[str, Any]] = []
        self._engagement_missions: List[Dict[str, Any]] = []
        self._engagement_runs: List[Dict[str, Any]] = []
        self._engagement_findings: List[Dict[str, Any]] = []
        self._engagements_loading = False
        self._engagements_list_loading = False
        self._engagements_loaded = False
        self._engagement_acting = False
        self._engagement_reselect_id = ""
        self._engagement_pending_project = ""
        self._engagement_widget = w
        return w

    # ── project list ──────────────────────────────────────────────────────────

    def _refresh_engagement_projects(self):
        if self._engagements_loading:
            return
        self._engagements_loading = True
        self._set_busy(True)
        self._run_async(self._query_engagement_projects,
                        self._on_engagement_projects_loaded)

    @staticmethod
    def _query_engagement_projects() -> dict:
        try:
            from core.engagement_store import EngagementStore
            projects = sorted({
                str(e.get("project") or "")
                for e in EngagementStore().list_engagements()
                if e.get("project")
            })
            return {"projects": projects}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_engagement_projects_loaded(self, result: dict):
        self._engagements_loading = False
        self._engagements_loaded = True
        self._set_busy(False)
        if result.get("error"):
            self.engagement_status.setText(f"Load error: {result['error']}")
            return
        pending = getattr(self, "_engagement_pending_project", "")
        self._engagement_pending_project = ""
        current = pending or self.engagement_project.currentData()
        self.engagement_project.blockSignals(True)
        self.engagement_project.clear()
        for project in result.get("projects", []):
            self.engagement_project.addItem(project, project)
        idx = self.engagement_project.findData(current)
        self.engagement_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.engagement_project.blockSignals(False)
        if self.engagement_project.count() == 0:
            self.engagement_status.setText("No projects with engagements")
            self._populate_engagements({"engagements": []})
            return
        self._on_engagement_project_changed()

    def _on_engagement_project_changed(self, *args):
        project = self.engagement_project.currentData()
        if project:
            self._refresh_engagements(project)

    # ── engagements for a project ───────────────────────────────────────────────

    def _refresh_engagements(self, project: str):
        if self._engagements_list_loading:
            return
        self._engagements_list_loading = True
        self._run_async(lambda p=project: self._query_engagements(p),
                        self._on_engagements_loaded)

    @staticmethod
    def _query_engagements(project: str) -> dict:
        try:
            from core.audit_store import AuditRunStore
            from core.engagement_links import resolve_links
            from core.engagement_store import EngagementStore
            from core.findings_store import FindingsStore
            from core.mission_store import MissionStore
            engagements = EngagementStore().list_engagements(project)
            mstore, astore, fstore = (MissionStore(), AuditRunStore(),
                                      FindingsStore())
            try:
                missions = mstore.list_missions(project)
            except Exception:  # noqa: BLE001 — link sources are best-effort
                missions = []
            try:
                runs = astore.list_runs(project)
            except Exception:  # noqa: BLE001
                runs = []
            try:
                findings = fstore.active_findings(project)
            except Exception:  # noqa: BLE001
                findings = []
            for e in engagements:
                try:
                    e["_links"] = resolve_links(
                        e.get("payload") or {}, mission_store=mstore,
                        audit_store=astore, findings_store=fstore)
                except Exception:  # noqa: BLE001 — annotation is best-effort
                    e["_links"] = {}
            return {"project": project, "engagements": engagements,
                    "missions": missions, "runs": runs, "findings": findings}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_engagements_loaded(self, result: dict):
        self._engagements_list_loading = False
        if result.get("error"):
            self.engagement_status.setText(f"Load error: {result['error']}")
            self._populate_engagements({"engagements": []})
            return
        self._populate_engagements(result)
        self.engagement_status.setText(
            f"{len(result.get('engagements') or [])} engagement(s)")

    def _populate_engagements(self, result: dict):
        self._engagement_rows = list(result.get("engagements") or [])
        self._engagement_missions = list(result.get("missions") or [])
        self._engagement_runs = list(result.get("runs") or [])
        self._engagement_findings = list(result.get("findings") or [])

        self.engagement_table.setRowCount(0)
        for e in self._engagement_rows:
            payload = e.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            row = self.engagement_table.rowCount()
            self.engagement_table.insertRow(row)
            n_links = (len(payload.get("linked_mission_ids") or [])
                       + len(payload.get("linked_audit_run_ids") or [])
                       + len(payload.get("linked_finding_ids") or []))
            values = [
                str(e.get("status") or ""),
                str(e.get("client") or payload.get("client") or ""),
                str(n_links),
                str(e.get("updated_at") or ""),
                str(e.get("id") or ""),
            ]
            for col, value in enumerate(values):
                self.engagement_table.setItem(row, col, QTableWidgetItem(value))

        # repopulate link-source combos
        self.engagement_link_mission.clear()
        for m in self._engagement_missions:
            mid = str(m.get("id") or "")
            if mid:
                self.engagement_link_mission.addItem(
                    f"{mid} ({m.get('status', '')})", mid)
        self.engagement_link_run.clear()
        for r in self._engagement_runs:
            rid = str(r.get("id") or "")
            if rid:
                self.engagement_link_run.addItem(f"{rid} ({r.get('status', '')})", rid)
        self.engagement_link_finding.clear()
        for f in self._engagement_findings:
            fid = str(f.get("id") or "")
            if fid:
                self.engagement_link_finding.addItem(
                    f"{fid}  {f.get('title', '')}".strip(), fid)

        self.engagement_detail.clear()
        self.engagement_advance_status.clear()

        reselect = getattr(self, "_engagement_reselect_id", "")
        self._engagement_reselect_id = ""
        reselected = False
        if reselect:
            for i, e in enumerate(self._engagement_rows):
                if str(e.get("id") or "") == reselect:
                    self.engagement_table.selectRow(i)
                    reselected = True
                    break
        if not reselected:
            self._update_engagement_actions()

    # ── selection / detail ──────────────────────────────────────────────────────

    def _selected_engagement(self) -> dict:
        sel = self.engagement_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        return self._engagement_rows[idx] if 0 <= idx < len(self._engagement_rows) else {}

    def _on_engagement_selected(self):
        e = self._selected_engagement()
        if not e:
            self.engagement_detail.clear()
            self.engagement_advance_status.clear()
            self._update_engagement_actions()
            return
        payload = e.get("payload")
        payload = payload if isinstance(payload, dict) else {}
        scope = payload.get("scope") or {}
        roe = payload.get("roe") or {}
        auth = payload.get("authorization") or {}
        lines = [
            f"Engagement: {e.get('id', '')}",
            f"Client:     {payload.get('client', '')}",
            f"Project:    {payload.get('project', '')}",
            f"Status:     {e.get('status', '')}",
            f"Auth:       {'accepted' if auth.get('accepted') else 'NOT accepted'}"
            f" (by {auth.get('authorized_by') or '—'}, ref {auth.get('reference') or '—'})",
            f"Scope:      domains {', '.join(scope.get('allowed_domains') or []) or '—'}"
            f"; ips {', '.join(scope.get('allowed_ips') or []) or '—'}",
            f"ROE:        {'passive-only' if roe.get('passive_only') else 'active allowed'}"
            f"; rate {roe.get('rate_limit') or '—'}; window {roe.get('window') or '—'}",
            f"Missions:   {', '.join(payload.get('linked_mission_ids') or []) or '—'}",
            f"Runs:       {', '.join(payload.get('linked_audit_run_ids') or []) or '—'}",
            f"Findings:   {', '.join(payload.get('linked_finding_ids') or []) or '—'}",
        ]
        links = e.get("_links") or {}
        stale = (list(links.get("stale_missions") or [])
                 + list(links.get("stale_runs") or [])
                 + list(links.get("stale_findings") or []))
        if stale:
            lines.append(f"⚠ Stale links: {', '.join(stale)}")
        self.engagement_detail.setPlainText("\n".join(lines))

        status = str(e.get("status") or "").strip().lower()
        targets = sorted(ENGAGEMENT_TRANSITIONS.get(status, frozenset()))
        self.engagement_advance_status.clear()
        for target in targets:
            self.engagement_advance_status.addItem(target, target)
        self._update_engagement_actions()

    def _update_engagement_actions(self):
        e = self._selected_engagement()
        idle = bool(e) and not self._engagement_acting
        self.btn_engagement_advance.setEnabled(
            idle and self.engagement_advance_status.count() > 0)
        self.btn_engagement_link_mission.setEnabled(
            idle and self.engagement_link_mission.count() > 0)
        self.btn_engagement_link_run.setEnabled(
            idle and self.engagement_link_run.count() > 0)
        self.btn_engagement_link_finding.setEnabled(
            idle and self.engagement_link_finding.count() > 0)
        for btn in (self.btn_engagement_report_json, self.btn_engagement_report_md,
                    self.btn_engagement_report_html):
            btn.setEnabled(idle)
        links = e.get("_links") or {} if e else {}
        has_stale = bool(links.get("stale_missions") or links.get("stale_runs")
                         or links.get("stale_findings"))
        self.btn_engagement_prune.setEnabled(idle and has_stale)

    # ── mutations ───────────────────────────────────────────────────────────────

    def _begin_engagement_action(self) -> dict:
        e = self._selected_engagement()
        if not e or self._engagement_acting:
            return {}
        payload = e.get("payload")
        if not isinstance(payload, dict):
            return {}
        self._engagement_reselect_id = str(e.get("id") or "")
        self._engagement_acting = True
        self._update_engagement_actions()
        self._set_busy(True)
        return payload

    def _advance_engagement(self):
        payload = self._begin_engagement_action()
        if not payload:
            return
        target = self.engagement_advance_status.currentData()
        self.engagement_status.setText(f"Advancing to {target}...")
        self._run_async(
            lambda p=payload, t=target: self._do_advance_engagement(p, t),
            self._on_engagement_action_done)

    @staticmethod
    def _do_advance_engagement(payload: Dict[str, Any], target: str) -> dict:
        try:
            from core.engagement import advance_engagement_status
            from core.engagement_store import EngagementStore
            EngagementStore().save_engagement(
                advance_engagement_status(payload, str(target)))
            return {"ok": f"status → {target}"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _link_engagement(self, kind: str):
        payload = self._begin_engagement_action()
        if not payload:
            return
        combo = {"mission": self.engagement_link_mission,
                 "audit_run": self.engagement_link_run,
                 "finding": self.engagement_link_finding}[kind]
        ref_id = combo.currentData()
        self.engagement_status.setText(f"Linking {kind} {ref_id}...")
        self._run_async(
            lambda p=payload, k=kind, r=ref_id: self._do_link_engagement(p, k, r),
            self._on_engagement_action_done)

    @staticmethod
    def _do_link_engagement(payload: Dict[str, Any], kind: str, ref_id: str) -> dict:
        try:
            from core import engagement_links as el
            from core.engagement_store import EngagementStore
            linker = {"mission": el.link_mission_checked,
                      "audit_run": el.link_audit_run_checked,
                      "finding": el.link_finding_checked}[kind]
            EngagementStore().save_engagement(linker(payload, str(ref_id)))
            return {"ok": f"linked {kind} {ref_id}"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _prune_engagement_links(self):
        payload = self._begin_engagement_action()
        if not payload:
            return
        self.engagement_status.setText("Removing stale links...")
        self._run_async(lambda p=payload: self._do_prune_engagement_links(p),
                        self._on_engagement_action_done)

    @staticmethod
    def _do_prune_engagement_links(payload: Dict[str, Any]) -> dict:
        try:
            from core.engagement_links import prune_stale_links
            from core.engagement_store import EngagementStore
            out = prune_stale_links(payload)
            EngagementStore().save_engagement(out["engagement"])
            removed = (len(out["removed_missions"]) + len(out["removed_runs"])
                       + len(out["removed_findings"]))
            return {"ok": f"removed {removed} stale link(s)"}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_engagement_action_done(self, result: dict):
        self._engagement_acting = False
        self._set_busy(False)
        if result.get("error"):
            self.engagement_status.setText(f"Action failed: {result['error']}")
            self._update_engagement_actions()
            return
        self.engagement_status.setText(result.get("ok") or "Done")
        project = self.engagement_project.currentData()
        if project:
            self._refresh_engagements(project)

    # ── create ─────────────────────────────────────────────────────────────────

    def _create_engagement(self):
        if self._engagement_acting:
            return
        client = self.engagement_create_client.text().strip()
        project = self.engagement_create_project.text().strip()
        if not client or not project:
            self.engagement_status.setText("Client and project are required")
            return
        scope = {"allowed_domains": [d.strip() for d
                                     in self.engagement_create_domains.text().split(",")
                                     if d.strip()]}
        roe = {
            "active_scan_enabled": self.engagement_create_active.isChecked(),
            "passive_only": self.engagement_create_passive.isChecked(),
            "rate_limit": self.engagement_create_rate.text().strip() or None,
        }
        authorization = {
            "accepted": self.engagement_create_accepted.isChecked(),
            "authorized_by": self.engagement_create_authby.text().strip(),
        }
        self._engagement_acting = True
        self._update_engagement_actions()
        self.btn_engagement_create.setEnabled(False)
        self._set_busy(True)
        self.engagement_status.setText("Creating engagement...")
        self._run_async(
            lambda c=client, p=project, s=scope, r=roe, a=authorization:
                self._do_create_engagement(c, p, s, r, a),
            self._on_engagement_create_done)

    @staticmethod
    def _do_create_engagement(client, project, scope, roe, authorization) -> dict:
        try:
            from core.engagement import create_engagement, validate_engagement
            from core.engagement_store import EngagementStore
            engagement = create_engagement(client, project, scope=scope, roe=roe,
                                           authorization=authorization)
            check = validate_engagement(engagement)
            if not check["valid"]:
                return {"error": "invalid: " + "; ".join(check["errors"])}
            saved = EngagementStore().save_engagement(engagement)
            return {"ok": f"created {saved['id']}", "project": project}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _on_engagement_create_done(self, result: dict):
        self._engagement_acting = False
        self._set_busy(False)
        self.btn_engagement_create.setEnabled(True)
        if result.get("error"):
            self.engagement_status.setText(f"Create failed: {result['error']}")
            self._update_engagement_actions()
            return
        self.engagement_status.setText(result.get("ok") or "Created")
        self.engagement_create_client.clear()
        self.engagement_create_project.clear()
        self._engagement_pending_project = result.get("project") or ""
        self._refresh_engagement_projects()

    # ── report export ────────────────────────────────────────────────────────────

    def _export_engagement_report(self, fmt: str):
        e = self._selected_engagement()
        payload = e.get("payload") if e else None
        if not isinstance(payload, dict):
            self.engagement_status.setText("Select an engagement first")
            return
        ext = {"json": "json", "md": "md", "html": "html"}[fmt]
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export Engagement Report {fmt.upper()}",
            f"engagement_report.{ext}", f"{fmt.upper()} Files (*.{ext})")
        if not path:
            return
        try:
            text = self._render_engagement_report(payload, fmt)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception as e:  # noqa: BLE001
            self.engagement_status.setText(f"Export failed: {e}")
            return
        self.engagement_status.setText(f"Exported engagement report: {path}")

    @staticmethod
    def _render_engagement_report(payload: Dict[str, Any], fmt: str) -> str:
        from core import engagement_report
        report = engagement_report.build_engagement_report(payload)
        renderer = {
            "json": engagement_report.render_json,
            "md": engagement_report.render_markdown,
            "html": engagement_report.render_html,
        }[fmt]
        return renderer(report)
