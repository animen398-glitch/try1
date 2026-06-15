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
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton

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

        ctrl.addStretch()
        self.findings_status = QLabel("Активных: 0 / 0")
        ctrl.addWidget(self.findings_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip("Сохранить текущий (отфильтрованный) список находок в CSV.")
        btn_export.clicked.connect(self._export_findings_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_findings)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── findings table ──────────────────────────────────────────────────
        self.findings_table = QTableWidget(0, len(self.FINDINGS_COLUMNS))
        self.findings_table.setHorizontalHeaderLabels(self.FINDINGS_COLUMNS)
        self.findings_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setAlternatingRowColors(True)
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # title fills space
        self.findings_table.itemSelectionChanged.connect(
            self._on_finding_row_selected)
        layout.addWidget(self.findings_table, stretch=1)

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

        # ── detail / history panel ──────────────────────────────────────────
        detail_grp = SectionGroupBox("Детали и история выбранной находки")
        detail_layout = QVBoxLayout()
        self.findings_detail = ResultsDisplay()
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

    def _apply_findings_filter(self, *args):
        if self._findings_table_loading:
            self._findings_filter_pending = True
            return
        self._findings_table_loading = True
        self._set_busy(True)
        project = self.findings_project.currentData()
        status = self.findings_status_filter.currentData()
        severity = self.findings_severity_filter.currentData()
        self._run_async(
            lambda p=project, s=status, v=severity: self._query_findings_table(p, s, v),
            self._on_findings_table_loaded,
        )

    @staticmethod
    def _query_findings_table(project, status, severity) -> dict:
        try:
            from core.findings_sla import annotate as annotate_sla
            store = FindingsStore()
            rows = store.list_findings(project=project, status=status,
                                       severity=severity)
            annotate_sla(rows)   # add the derived 'sla' field per finding
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
            self.findings_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        summary = result.get('summary', {})
        self._findings_chains = result.get('finding_chains', {})
        self.findings_status.setText(
            f"Активных: {summary.get('active', 0)} / {summary.get('total', 0)}"
            f"  ·  показано: {len(result.get('rows', []))}")
        self._populate_findings_table(result.get('rows', []))

    def _populate_findings_table(self, rows: list):
        self._findings_records = rows
        self.findings_table.setRowCount(0)
        for rec in rows:
            r = self.findings_table.rowCount()
            self.findings_table.insertRow(r)
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
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 0:
                    color = theme.severity_color(severity)
                    if color:
                        item.setForeground(QColor(color))
                elif col == 6 and sla.get('breached'):
                    # Overdue findings stand out in the SLA column.
                    item.setForeground(QColor(theme.severity_color('critical')))
                self.findings_table.setItem(r, col, item)
        self.findings_detail.clear()
        self.btn_findings_apply.setEnabled(False)

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_finding(self) -> dict:
        sel = self.findings_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._findings_records)):
            return {}
        return self._findings_records[idx]

    def _on_finding_row_selected(self):
        rec = self._selected_finding()
        if not rec:
            self.btn_findings_apply.setEnabled(False)
            return
        self.btn_findings_apply.setEnabled(True)
        # Preselect the current status in the change combo.
        i = self.findings_new_status.findData(rec.get('status'))
        if i >= 0:
            self.findings_new_status.setCurrentIndex(i)
        self._show_finding_detail(rec)
        # Load the audit trail off the GUI thread.
        fid = rec.get('id')
        if fid:
            self._run_async(lambda f=fid: self._query_finding_events(f),
                            self._on_finding_events_loaded)

    @staticmethod
    def _query_finding_events(finding_id: str) -> dict:
        try:
            return {'id': finding_id, 'events': FindingsStore().events(finding_id)}
        except Exception as e:  # noqa: BLE001
            return {'id': finding_id, 'error': str(e)}

    def _on_finding_events_loaded(self, result: dict):
        rec = self._selected_finding()
        # Discard if the selection moved on while the query ran.
        if not rec or rec.get('id') != result.get('id'):
            return
        self._show_finding_detail(rec, result.get('events'))

    def _show_finding_detail(self, rec: dict, events=None):
        lines = [
            f"Заголовок:  {rec.get('title', '')}",
            f"Категория:  {rec.get('category', '')}   "
            f"Severity: {rec.get('severity', '')}   "
            f"Статус: {STATUS_LABELS.get(rec.get('status'), rec.get('status', ''))}",
            f"Rule:       {rec.get('rule_id', '')}",
            f"ID:         {rec.get('id', '')}",
            f"Обнаружено: {rec.get('first_seen_at', '')} → {rec.get('last_seen_at', '')}",
            f"SLA:        {format_sla(rec.get('sla') or {})}",
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
        if events:
            lines.append("История:")
            for ev in events:
                transition = ''
                if ev.get('from_status') or ev.get('to_status'):
                    transition = f" {ev.get('from_status') or '—'}→{ev.get('to_status') or '—'}"
                note = f"  ({ev['note']})" if ev.get('note') else ''
                lines.append(f"  {ev.get('at', '')}  {ev.get('type', '')}{transition}{note}")
        self.findings_detail.setPlainText("\n".join(lines))

    # ── status change (write) ──────────────────────────────────────────────────

    def _apply_finding_status(self):
        rec = self._selected_finding()
        fid = rec.get('id')
        if not fid:
            return
        new_status = self.findings_new_status.currentData()
        note = self.findings_note.text().strip() or None
        self.btn_findings_apply.setEnabled(False)
        self._set_busy(True)
        self._run_async(
            lambda f=fid, s=new_status, n=note: self._write_finding_status(f, s, n),
            self._on_finding_status_written,
        )

    @staticmethod
    def _write_finding_status(finding_id: str, status: str, note) -> dict:
        try:
            FindingsStore().set_status(finding_id, status, note=note, source='user')
            return {'ok': True}
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
