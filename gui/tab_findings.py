"""Findings tab — the Findings Management view (roadmap F1, task T1.5).

A finding now lives across scans in ``data/findings.db`` (core/findings_store.py)
with a lifecycle (OPEN → FIXED/IGNORED/FALSE_POSITIVE) and an audit trail. This
tab is the human side of that store: pick a project, filter by status/severity,
read the evidence + event history of a finding, and change its triage status
(which feeds back into the risk engine — inactive statuses stop counting).

Thin UI mixin folded into MainWindow: every DB read/write runs off the GUI
thread via ``_run_async`` (the SQLite connection is opened and closed inside the
worker), mirroring the Dashboard tab. Formatting that isn't pure presentation
stays in core (status labels live in core.findings_store).
"""

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.findings_sla import label as format_sla
from core.findings_store import (
    FindingsStore, SEVERITY_ORDER, STATUS_LABELS, STATUSES,
)
from gui import theme
from gui.ui_components import (
    LinkTextBrowser, SectionGroupBox, StyledButton, TablePaginator,
)

# Severity → cell colour. The canonical (light) palette now lives in gui.theme;
# this alias is kept for backward compatibility. Rendering uses
# ``theme.severity_color`` so the dark theme gets readable (brighter) variants.
_SEVERITY_COLORS = theme.LIGHT_SEVERITY


class FindingsTabMixin:
    """Builds and drives the Findings Management tab."""

    FINDINGS_COLUMNS = ["Severity", "Категория", "Заголовок", "Статус",
                        "Перв. обнаружено", "Посл. обнаружено", "SLA"]

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── filter / control row ────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.findings_project = QComboBox()
        self.findings_project.setMinimumWidth(180)
        self.findings_project.currentIndexChanged.connect(self._apply_findings_filter)
        ctrl.addWidget(self.findings_project)

        ctrl.addWidget(QLabel("Статус:"))
        self.findings_status_filter = QComboBox()
        self.findings_status_filter.addItem("Все", None)
        for st in STATUSES:
            self.findings_status_filter.addItem(STATUS_LABELS.get(st, st), st)
        self.findings_status_filter.currentIndexChanged.connect(
            self._apply_findings_filter)
        ctrl.addWidget(self.findings_status_filter)

        ctrl.addWidget(QLabel("Severity:"))
        self.findings_severity_filter = QComboBox()
        self.findings_severity_filter.addItem("Все", None)
        for sev in SEVERITY_ORDER:
            self.findings_severity_filter.addItem(sev, sev)
        self.findings_severity_filter.currentIndexChanged.connect(
            self._apply_findings_filter)
        ctrl.addWidget(self.findings_severity_filter)

        ctrl.addWidget(QLabel("Поиск:"))
        self.findings_search = QLineEdit()
        self.findings_search.setPlaceholderText("текст в заголовке / rule / категории")
        self.findings_search.setClearButtonEnabled(True)
        self.findings_search.setMaximumWidth(220)
        # Search on Enter (and when the clear button empties it) — not per keystroke.
        self.findings_search.returnPressed.connect(self._apply_findings_filter)
        self.findings_search.textChanged.connect(self._on_search_text_changed)
        ctrl.addWidget(self.findings_search)

        ctrl.addStretch()
        self.findings_status = QLabel("Активных: 0 / 0")
        ctrl.addWidget(self.findings_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip("Сохранить текущий (отфильтрованный) список находок в CSV.")
        btn_export.clicked.connect(self._export_findings_csv)
        ctrl.addWidget(btn_export)
        btn_export_acc = StyledButton("Export acceptances", style='secondary')
        btn_export_acc.setToolTip(
            "Экспортировать принятия риска проекта (reason/approver/until/expired) в CSV.")
        btn_export_acc.clicked.connect(self._export_acceptances_csv)
        ctrl.addWidget(btn_export_acc)
        btn_sarif = StyledButton("Export SARIF", style='secondary')
        btn_sarif.setToolTip(
            "Сохранить находки в SARIF 2.1.0 (GitHub code scanning / CI / IDE).")
        btn_sarif.clicked.connect(self._export_findings_sarif)
        ctrl.addWidget(btn_sarif)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_findings)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── findings table ──────────────────────────────────────────────────
        self.findings_table = QTableWidget(0, len(self.FINDINGS_COLUMNS))
        self.findings_table.setHorizontalHeaderLabels(self.FINDINGS_COLUMNS)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # Extended selection so several findings can be triaged in one action
        # (bulk status / assign); a single-row selection behaves exactly as before.
        self.findings_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setAlternatingRowColors(True)
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # title fills space
        self.findings_table.itemSelectionChanged.connect(
            self._on_finding_row_selected)
        layout.addWidget(self.findings_table, stretch=1)
        # Page large finding lists so populating the widget never freezes the UI;
        # the full (filtered/sorted) list is kept for selection + CSV export.
        self._findings_paginator = TablePaginator(
            self.findings_table, self._render_findings_row,
            on_page_changed=self._on_findings_page_changed)
        layout.addWidget(self._findings_paginator.widget)

        # ── status-change row (acts on the selected finding) ────────────────
        change_grp = SectionGroupBox("Сменить статус выбранной находки")
        change_row = QHBoxLayout()
        change_row.addWidget(QLabel("Новый статус:"))
        self.findings_new_status = QComboBox()
        for st in STATUSES:
            self.findings_new_status.addItem(STATUS_LABELS.get(st, st), st)
        change_row.addWidget(self.findings_new_status)
        change_row.addWidget(QLabel("Примечание:"))
        self.findings_note = QLineEdit()
        self.findings_note.setPlaceholderText("необязательно")
        change_row.addWidget(self.findings_note, stretch=1)
        self.btn_findings_apply = StyledButton("Применить")
        self.btn_findings_apply.setEnabled(False)
        self.btn_findings_apply.clicked.connect(self._apply_finding_status)
        change_row.addWidget(self.btn_findings_apply)
        change_grp.setLayout(change_row)
        layout.addWidget(change_grp)

        # ── triage row: assignment + comment (act on the selected finding) ───
        triage_grp = SectionGroupBox("Триаж выбранной находки")
        triage_row = QHBoxLayout()
        triage_row.addWidget(QLabel("Исполнитель:"))
        self.findings_assignee = QLineEdit()
        self.findings_assignee.setPlaceholderText("кому назначить (пусто = снять)")
        triage_row.addWidget(self.findings_assignee)
        self.btn_findings_assign = StyledButton("Назначить", style='secondary')
        self.btn_findings_assign.setEnabled(False)
        self.btn_findings_assign.clicked.connect(self._apply_finding_assign)
        triage_row.addWidget(self.btn_findings_assign)
        triage_row.addWidget(QLabel("Комментарий:"))
        self.findings_comment = QLineEdit()
        self.findings_comment.setPlaceholderText("добавить комментарий")
        triage_row.addWidget(self.findings_comment, stretch=1)
        self.btn_findings_comment = StyledButton("Добавить", style='secondary')
        self.btn_findings_comment.setEnabled(False)
        self.btn_findings_comment.clicked.connect(self._apply_finding_comment)
        triage_row.addWidget(self.btn_findings_comment)
        triage_grp.setLayout(triage_row)
        layout.addWidget(triage_grp)

        # ── risk acceptance (v1): time-boxed accept of the selected finding ──
        accept_grp = SectionGroupBox("Принятие риска (с истечением)")
        accept_row = QHBoxLayout()
        accept_row.addWidget(QLabel("Причина:"))
        self.findings_accept_reason = QLineEdit()
        self.findings_accept_reason.setPlaceholderText("почему риск принят")
        accept_row.addWidget(self.findings_accept_reason, stretch=1)
        accept_row.addWidget(QLabel("Кем:"))
        self.findings_accept_approver = QLineEdit()
        self.findings_accept_approver.setMaximumWidth(120)
        accept_row.addWidget(self.findings_accept_approver)
        accept_row.addWidget(QLabel("До:"))
        self.findings_accept_until = QLineEdit()
        self.findings_accept_until.setPlaceholderText("YYYY-MM-DD")
        self.findings_accept_until.setMaximumWidth(110)
        accept_row.addWidget(self.findings_accept_until)
        self.btn_findings_accept = StyledButton("Принять риск", style='secondary')
        self.btn_findings_accept.setEnabled(False)
        self.btn_findings_accept.clicked.connect(self._apply_finding_accept)
        accept_row.addWidget(self.btn_findings_accept)
        self.btn_findings_accept_clear = StyledButton("Снять", style='secondary')
        self.btn_findings_accept_clear.setEnabled(False)
        self.btn_findings_accept_clear.clicked.connect(self._clear_finding_accept)
        accept_row.addWidget(self.btn_findings_accept_clear)
        accept_grp.setLayout(accept_row)
        layout.addWidget(accept_grp)

        # ── detail / history panel ──────────────────────────────────────────
        detail_grp = SectionGroupBox("Детали и история выбранной находки")
        detail_layout = QVBoxLayout()
        self.findings_detail = LinkTextBrowser()
        self.findings_detail.setMaximumHeight(180)
        self.findings_detail.setPlaceholderText(
            "Выберите находку, чтобы увидеть улики и историю статусов")
        detail_layout.addWidget(self.findings_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # Full rows backing the table, so a selection can show untruncated data.
        self._findings_records: list = []
        # F-K3: finding_id → resolved asset/infra chain (correlation), filled per
        # single-project load so the detail panel can show where a finding lives.
        self._findings_chains: dict = {}
        self._findings_widget = w
        return w

    # ── load ────────────────────────────────────────────────────────────────

    def _export_findings_csv(self):
        """Save the currently loaded (filtered) findings to a CSV file."""
        from datetime import datetime

        from core.report_export import findings_csv
        rows = self._findings_records
        if not rows:
            self.findings_status.setText("Нечего экспортировать")
            return
        default = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(findings_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.findings_status.setText(f"Экспортировано находок: {len(rows)}")

    def _export_acceptances_csv(self):
        """Save the project's risk acceptances (client/audit deliverable) to CSV.
        The store read runs off the GUI thread; the file dialog stays on it."""
        from datetime import datetime
        project = self.findings_project.currentData()
        label = project or 'all'
        default = f"acceptances_{label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export acceptances CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        self._set_busy(True)
        self._run_async(lambda p=project, pa=path: self._write_acceptances_csv(p, pa),
                        self._on_acceptances_exported)

    @staticmethod
    def _write_acceptances_csv(project, path) -> dict:
        try:
            from core.findings_store import FindingsStore
            from core.report_export import risk_acceptances_csv
            rows = FindingsStore().risk_acceptances(project)
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(risk_acceptances_csv(rows))
            return {'ok': True, 'count': len(rows)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_acceptances_exported(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            self.findings_status.setText(f"Ошибка экспорта: {result['error']}")
            return
        self.findings_status.setText(
            f"Экспортировано принятий риска: {result.get('count', 0)}")

    def _export_findings_sarif(self):
        """Save the currently loaded (filtered) findings to a SARIF 2.1.0 file."""
        from datetime import datetime

        from core.config import APP_VERSION
        from core.report_export import findings_sarif
        rows = self._findings_records
        if not rows:
            self.findings_status.setText("Нечего экспортировать")
            return
        default = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export SARIF", default, "SARIF Files (*.sarif *.json)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(findings_sarif(rows, tool_version=APP_VERSION))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить SARIF: {e}")
            return
        self.findings_status.setText(f"Экспортировано (SARIF): {len(rows)}")

    def _refresh_findings(self):
        if self._findings_loading:
            return
        self._findings_loading = True
        self._set_busy(True)
        self._run_async(self._query_findings, self._on_findings_loaded)

    @staticmethod
    def _query_findings() -> dict:
        # Off-GUI-thread read; the store opens/uses/closes its connection here.
        try:
            store = FindingsStore()
            return {'projects': store.projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_findings_loaded(self, result: dict):
        self._findings_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._findings_loaded = False  # allow retry on next open/refresh
            self.findings_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._findings_loaded = True

        # Repopulate the project selector, preserving the current choice.
        current = self.findings_project.currentData()
        self.findings_project.blockSignals(True)
        self.findings_project.clear()
        self.findings_project.addItem("Все проекты", None)
        for p in result.get('projects', []):
            self.findings_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.findings_project.findData(current)
        self.findings_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.findings_project.blockSignals(False)

        self._apply_findings_filter()

    # ── filter / populate ─────────────────────────────────────────────────────

    def _on_search_text_changed(self, text: str):
        # Re-filter immediately when the box is cleared; otherwise wait for Enter.
        if not text.strip():
            self._apply_findings_filter()

    def _apply_findings_filter(self, *args):
        if self._findings_table_loading:
            self._findings_filter_pending = True
            return
        self._findings_table_loading = True
        self._set_busy(True)
        project = self.findings_project.currentData()
        status = self.findings_status_filter.currentData()
        severity = self.findings_severity_filter.currentData()
        query = self.findings_search.text().strip() or None
        self._run_async(
            lambda p=project, s=status, v=severity, q=query:
                self._query_findings_table(p, s, v, q),
            self._on_findings_table_loaded,
        )

    @staticmethod
    def _query_findings_table(project, status, severity, query=None) -> dict:
        try:
            from core import threat_intel
            from core.findings_sla import annotate as annotate_sla
            store = FindingsStore()
            rows = store.list_findings(project=project, status=status,
                                       severity=severity, query=query)
            # KEV/EPSS threat block from the offline cache first (cold cache =
            # no-op), so the detail badge shows it and the SLA clock below is
            # tightened for known-exploited findings — consistent with the report.
            rows = threat_intel.annotate_offline(rows)
            # reopen-aware SLA clock (see FindingsStore.reopen_dates)
            annotate_sla(rows, reopened=store.reopen_dates(project))
            summary = store.summary(project)
            # F-K3: resolve each finding's asset/infra chain for a single project
            # (cross-store correlation). Skipped for "all projects" (None).
            finding_chains: dict = {}
            if project:
                try:
                    from core.asset_store import AssetStore
                    from core.correlation import build_correlation
                    assets = AssetStore().list_assets(project=project)
                    finding_chains = build_correlation(
                        rows, assets).get('finding_chains', {})
                except Exception:   # noqa: BLE001 — correlation is best-effort
                    finding_chains = {}
            return {'rows': rows, 'summary': summary, 'project': project,
                    'status': status, 'severity': severity,
                    'finding_chains': finding_chains}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_findings_table_loaded(self, result: dict):
        self._findings_table_loading = False
        self._set_busy(False)
        if self._findings_filter_pending:
            self._findings_filter_pending = False
            self._apply_findings_filter()
            return
        if result.get('error'):
            self._findings_chains = {}
            self._populate_findings_table([])
            self.findings_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        summary = result.get('summary', {})
        self._findings_chains = result.get('finding_chains', {})
        self.findings_status.setText(
            f"Активных: {summary.get('active', 0)} / {summary.get('total', 0)}"
            f"  ·  показано: {len(result.get('rows', []))}")
        self._populate_findings_table(result.get('rows', []))

    @staticmethod
    def _render_findings_row(table, r: int, rec: dict):
        severity = str(rec.get('severity', '')).lower()
        status = rec.get('status', '')
        sla = rec.get('sla') or {}
        values = [
            severity,
            rec.get('category', ''),
            rec.get('title', ''),
            STATUS_LABELS.get(status, status),
            (rec.get('first_seen_at') or '')[:10],
            (rec.get('last_seen_at') or '')[:10],
            format_sla(sla),
        ]
        threat = rec.get('threat') if isinstance(rec.get('threat'), dict) else {}
        is_kev = bool(threat.get('kev'))
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 0:
                color = theme.severity_color(severity)
                if color:
                    item.setForeground(QColor(color))
            elif col == 6 and sla.get('breached'):
                # Overdue findings stand out in the SLA column.
                item.setForeground(QColor(theme.severity_color('critical')))
            if is_kev and col == 2:
                # In-list cue for a known-exploited finding (full badge in detail).
                item.setForeground(QColor(theme.severity_color('critical')))
                item.setToolTip("⚠ KEV — известно эксплуатируется в реальных атаках")
            table.setItem(r, col, item)

    def _populate_findings_table(self, rows: list):
        self._findings_records = rows          # full list — selection + CSV export
        self._findings_paginator.set_rows(rows)
        self.findings_detail.clear()
        self._set_triage_enabled(False)

    def _on_findings_page_changed(self):
        # A new page has no carried-over selection; clear the stale detail/triage.
        self.findings_detail.clear()
        self._set_triage_enabled(False)

    def _set_triage_enabled(self, enabled: bool):
        self.btn_findings_apply.setEnabled(enabled)
        self.btn_findings_assign.setEnabled(enabled)
        self.btn_findings_comment.setEnabled(enabled)
        self.btn_findings_accept.setEnabled(enabled)
        self.btn_findings_accept_clear.setEnabled(enabled)

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_finding(self) -> dict:
        sel = self.findings_table.selectionModel().selectedRows()
        if not sel:
            return {}
        # Map the table row to the full-list record via the paginator (the table
        # shows only the current page).
        return self._findings_paginator.record_at(sel[0].row()) or {}

    def _selected_findings(self) -> list:
        """All selected findings' records (current page), for bulk triage."""
        recs = []
        for idx in self.findings_table.selectionModel().selectedRows():
            rec = self._findings_paginator.record_at(idx.row())
            if rec:
                recs.append(rec)
        return recs

    def _on_finding_row_selected(self):
        rec = self._selected_finding()
        if not rec:
            self._set_triage_enabled(False)
            return
        self._set_triage_enabled(True)
        n_sel = len(self.findings_table.selectionModel().selectedRows())
        if n_sel > 1:
            # Multi-select: status/assign act on all; detail shows the first.
            self.findings_status.setText(f"Выбрано находок: {n_sel} (массовый триаж)")
        # Preselect the current status in the change combo.
        i = self.findings_new_status.findData(rec.get('status'))
        if i >= 0:
            self.findings_new_status.setCurrentIndex(i)
        self._show_finding_detail(rec)
        # Load the audit trail + triage state off the GUI thread.
        fid = rec.get('id')
        if fid:
            self._run_async(lambda f=fid: self._query_finding_events(f),
                            self._on_finding_events_loaded)

    @staticmethod
    def _query_finding_events(finding_id: str) -> dict:
        try:
            store = FindingsStore()
            return {'id': finding_id, 'events': store.events(finding_id),
                    'assignee': store.get_assignee(finding_id),
                    'comments': store.comments(finding_id),
                    'acceptance': store.risk_acceptance_state(finding_id)}
        except Exception as e:  # noqa: BLE001
            return {'id': finding_id, 'error': str(e)}

    def _on_finding_events_loaded(self, result: dict):
        rec = self._selected_finding()
        # Discard if the selection moved on while the query ran.
        if not rec or rec.get('id') != result.get('id'):
            return
        # Prefill the assignee field with the current value (empty = unassigned).
        self.findings_assignee.setText(result.get('assignee') or '')
        acc = result.get('acceptance') or {}
        # Prefill the acceptance fields so an edit starts from the current state.
        self.findings_accept_reason.setText(acc.get('reason') or '')
        self.findings_accept_approver.setText(acc.get('approver') or '')
        self.findings_accept_until.setText(acc.get('until') or '')
        self._show_finding_detail(rec, result.get('events'),
                                  assignee=result.get('assignee') or '',
                                  comments=result.get('comments') or [],
                                  acceptance=acc)

    def _show_finding_detail(self, rec: dict, events=None, *, assignee='',
                             comments=None, acceptance=None):
        lines = [
            f"Заголовок:  {rec.get('title', '')}",
            f"Категория:  {rec.get('category', '')}   "
            f"Severity: {rec.get('severity', '')}   "
            f"Статус: {STATUS_LABELS.get(rec.get('status'), rec.get('status', ''))}",
            f"Rule:       {rec.get('rule_id', '')}",
            f"ID:         {rec.get('id', '')}",
            f"Исполнитель: {assignee or '—'}",
            f"Обнаружено: {rec.get('first_seen_at', '')} → {rec.get('last_seen_at', '')}",
        ]
        acc = acceptance or {}
        if acc.get('accepted'):
            until = acc.get('until') or 'бессрочно'
            note = ' ⚠ ИСТЕКЛО' if acc.get('expired') else ''
            who = acc.get('approver') or '—'
            lines.append(f"Принятие риска: до {until} (кем: {who}){note}")
        # KEV/EPSS exploitability badge — the strongest "fix now" signal, shown
        # before SLA because it is what tightened the deadline (single wording via
        # threat_intel.threat_label). Absent for un-enriched / non-CVE findings.
        from core.threat_intel import threat_label
        badge = threat_label(rec.get('threat'))
        if badge:
            lines.append(f"⚠ Exploitability: {badge}")
        sla = rec.get('sla') or {}
        sla_line = f"SLA:        {format_sla(sla)}"
        if sla.get('tightened_by'):
            # Make the tightening explicit so the shorter deadline isn't a surprise.
            sla_line += (f"  (ужесточено: {sla['tightened_by'].upper()}, "
                         f"базовое {sla.get('base_sla_days')}д)")
        lines.append(sla_line)
        # F-O3: the finding "object" — description / impact / remediation (catalog,
        # with any producer-supplied text winning). Always present (generic
        # fallback), so a triager always sees what it is and how to fix it.
        from core.finding_knowledge import describe
        info = describe(rec.get('category', ''), rec.get('rule_id', ''),
                        rec.get('title', ''), rec.get('evidence'))
        lines += [
            f"Описание:   {info['description']}",
            f"Воздействие: {info['impact']}",
            f"Remediation: {info['remediation']}",
        ]
        evidence = rec.get('evidence')
        if isinstance(evidence, dict) and evidence:
            lines.append("Улики:")
            for k, v in evidence.items():
                lines.append(f"  {k}: {v}")
        # F-K3: where this finding lives — endpoint → host → ip → asn.
        chain = (self._findings_chains or {}).get(rec.get('id'))
        if chain:
            asn = chain.get('asn')
            if asn and chain.get('asn_name'):
                asn = f"{asn} ({chain['asn_name']})"
            trail = ' → '.join(str(x) for x in (
                chain.get('endpoint'), chain.get('host'), chain.get('ip'), asn) if x)
            if trail:
                lines.append(f"Цепочка:    {trail}")
        # Triage comments thread (rendered readably; the raw COMMENT events are
        # skipped in the history below to avoid showing their JSON note twice).
        if comments:
            lines.append("Комментарии:")
            for c in comments:
                who = c.get('author') or '—'
                lines.append(f"  [{(c.get('at') or '')[:16]}] {who}: {c.get('text', '')}")
        if events:
            lines.append("История:")
            for ev in events:
                if ev.get('type') == 'COMMENT':
                    continue   # shown in the Comments section above
                transition = ''
                if ev.get('from_status') or ev.get('to_status'):
                    transition = f" {ev.get('from_status') or '—'}→{ev.get('to_status') or '—'}"
                note = f"  ({ev['note']})" if ev.get('note') else ''
                lines.append(f"  {ev.get('at', '')}  {ev.get('type', '')}{transition}{note}")
        self.findings_detail.set_linkified("\n".join(lines))

    # ── status change (write) ──────────────────────────────────────────────────

    def _apply_finding_status(self):
        ids = [r.get('id') for r in self._selected_findings() if r.get('id')]
        if not ids:
            return
        new_status = self.findings_new_status.currentData()
        note = self.findings_note.text().strip() or None
        self.btn_findings_apply.setEnabled(False)
        self._set_busy(True)
        if len(ids) > 1:               # bulk over every selected finding
            self._run_async(
                lambda i=ids, s=new_status, n=note: self._write_finding_bulk_status(i, s, n),
                self._on_finding_status_written)
        else:
            self._run_async(
                lambda f=ids[0], s=new_status, n=note: self._write_finding_status(f, s, n),
                self._on_finding_status_written)

    @staticmethod
    def _write_finding_status(finding_id: str, status: str, note) -> dict:
        try:
            FindingsStore().set_status(finding_id, status, note=note, source='user')
            return {'ok': True}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    @staticmethod
    def _write_finding_bulk_status(ids, status: str, note) -> dict:
        try:
            out = FindingsStore().bulk_set_status(ids, status, note=note,
                                                  source='user')
            return {'ok': True, **out}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_finding_status_written(self, result: dict):
        self._set_busy(False)
        self.findings_note.clear()
        if result.get('error'):
            self.findings_status.setText(f"Ошибка смены статуса: {result['error']}")
            return
        # Reload so counts, the row's status and project tallies all refresh.
        self._refresh_findings()

    # ── triage: assignment + comment (write) ────────────────────────────────────

    def _apply_finding_assign(self):
        ids = [r.get('id') for r in self._selected_findings() if r.get('id')]
        if not ids:
            return
        who = self.findings_assignee.text().strip()
        self._set_triage_enabled(False)
        self._set_busy(True)
        if len(ids) > 1:               # bulk over every selected finding
            self._run_async(lambda i=ids, w=who: self._write_finding_bulk_assign(i, w),
                            self._on_triage_written)
        else:
            self._run_async(lambda f=ids[0], w=who: self._write_finding_assign(f, w),
                            self._on_triage_written)

    @staticmethod
    def _write_finding_assign(finding_id: str, assignee: str) -> dict:
        try:
            FindingsStore().assign(finding_id, assignee)
            return {'ok': True, 'msg': (f"назначено: {assignee}" if assignee
                                        else "назначение снято")}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    @staticmethod
    def _write_finding_bulk_assign(ids, assignee: str) -> dict:
        try:
            out = FindingsStore().bulk_assign(ids, assignee)
            n = len(out['updated'])
            return {'ok': True, 'msg': (f"назначено ({n}): {assignee}" if assignee
                                        else f"назначение снято ({n})")}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _apply_finding_comment(self):
        rec = self._selected_finding()
        fid = rec.get('id')
        if not fid:
            return
        text = self.findings_comment.text().strip()
        if not text:
            self.findings_status.setText("Комментарий пуст")
            return
        self._set_triage_enabled(False)
        self._set_busy(True)
        self._run_async(lambda f=fid, t=text: self._write_finding_comment(f, t),
                        self._on_triage_written)

    @staticmethod
    def _write_finding_comment(finding_id: str, text: str) -> dict:
        try:
            FindingsStore().add_comment(finding_id, text)
            return {'ok': True, 'msg': "комментарий добавлен"}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_triage_written(self, result: dict):
        self._set_busy(False)
        self.findings_comment.clear()
        if result.get('error'):
            self.findings_status.setText(f"Ошибка триажа: {result['error']}")
            self._set_triage_enabled(bool(self._selected_finding()))
            return
        self.findings_status.setText(result.get('msg') or "Готово")
        # Refresh the detail + triage state of the still-selected finding.
        self._on_finding_row_selected()

    # ── risk acceptance (v1): accept / revoke the selected finding ──────────────

    def _apply_finding_accept(self):
        rec = self._selected_finding()
        fid = rec.get('id')
        if not fid:
            return
        reason = self.findings_accept_reason.text().strip()
        approver = self.findings_accept_approver.text().strip()
        until = self.findings_accept_until.text().strip()
        self._set_triage_enabled(False)
        self._set_busy(True)
        self._run_async(
            lambda f=fid, r=reason, a=approver, u=until:
                self._write_finding_accept(f, r, a, u),
            self._on_triage_written)

    @staticmethod
    def _write_finding_accept(finding_id: str, reason: str, approver: str,
                              until: str) -> dict:
        try:
            FindingsStore().accept_risk(finding_id, reason=reason,
                                        approver=approver, until=until)
            return {'ok': True, 'msg': (f"риск принят до {until}" if until
                                        else "риск принят (бессрочно)")}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _clear_finding_accept(self):
        rec = self._selected_finding()
        fid = rec.get('id')
        if not fid:
            return
        self._set_triage_enabled(False)
        self._set_busy(True)
        self._run_async(lambda f=fid: self._write_finding_accept_clear(f),
                        self._on_triage_written)

    @staticmethod
    def _write_finding_accept_clear(finding_id: str) -> dict:
        try:
            FindingsStore().clear_risk_acceptance(finding_id)
            return {'ok': True, 'msg': "принятие риска снято"}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}
