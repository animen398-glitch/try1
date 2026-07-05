"""Risk Acceptances tab — the review surface for time-boxed risk acceptance.

Accepted risks were reachable only piecemeal (a finding's detail badge, a timeline
event when one expires, an Alert Center notification, the CSV export). This tab is
the consolidated review view: pick a project, read every accepted finding with its
reason/approver/until and — most importantly — an **expired** flag for the ones
whose acceptance has lapsed and need re-review. Revoke the selected acceptance or
export the list.

Thin UI mixin folded into MainWindow, mirroring the Remediation tab: every store
read/write runs off the GUI thread via ``_run_async`` (the SQLite connection is
opened and closed inside the worker). Acceptance state lives in
``core.findings_store`` (event-sourced, derive-on-read) — this file only renders
and dispatches. Review state, not a risk signal.
"""

from datetime import datetime

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QMessageBox, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from gui import theme
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton, TablePaginator,
)


class AcceptancesTabMixin:
    """Builds and drives the Risk Acceptances review tab."""

    ACC_COLUMNS = ["Severity", "Находка", "Кем принят", "До", "Статус"]

    # (rollup key -> caption); values derived from the loaded acceptances.
    ACC_ROLLUP = [
        ('total',   'Принято'),
        ('active',  'Действуют'),
        ('expired', 'Истекли'),
    ]

    def _build_acceptances_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.acc_project = QComboBox()
        self.acc_project.setMinimumWidth(220)
        self.acc_project.currentIndexChanged.connect(self._apply_acc_filter)
        ctrl.addWidget(self.acc_project)

        self.acc_expired_only = QCheckBox("Только истёкшие")
        self.acc_expired_only.setToolTip(
            "Показать только принятия риска, срок которых истёк — их нужно "
            "перепроверить. Счётчики выше остаются по всему проекту.")
        self.acc_expired_only.toggled.connect(self._apply_acc_view)
        ctrl.addWidget(self.acc_expired_only)

        ctrl.addStretch()
        self.acc_status = QLabel("Принято: 0")
        ctrl.addWidget(self.acc_status)
        self.btn_acc_export = StyledButton("Export CSV", style='secondary')
        self.btn_acc_export.setToolTip(
            "Экспортировать принятия риска проекта (reason/approver/until/expired).")
        self.btn_acc_export.clicked.connect(self._export_acc_csv)
        ctrl.addWidget(self.btn_acc_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_acceptances)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards ────────────────────────────────────────────────────
        rollup_row = FlowLayout()
        self.acc_rollup: dict = {}
        for key, title in self.ACC_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.acc_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── acceptances table ───────────────────────────────────────────────
        self.acc_table = QTableWidget(0, len(self.ACC_COLUMNS))
        self.acc_table.setHorizontalHeaderLabels(self.ACC_COLUMNS)
        self.acc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.acc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.acc_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.acc_table.verticalHeader().setVisible(False)
        self.acc_table.setAlternatingRowColors(True)
        header = self.acc_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)   # finding title fills
        self.acc_table.itemSelectionChanged.connect(self._on_acc_row_selected)
        layout.addWidget(self.acc_table, stretch=1)
        self._acc_paginator = TablePaginator(
            self.acc_table, self._render_acc_row,
            on_page_changed=self._on_acc_page_changed)
        layout.addWidget(self._acc_paginator.widget)

        # ── action row (acts on the selected acceptance) ────────────────────
        action_row = QHBoxLayout()
        self.btn_acc_revoke = StyledButton("Снять принятие")
        self.btn_acc_revoke.setToolTip(
            "Отозвать принятие риска выбранной находки (она снова считается активной).")
        self.btn_acc_revoke.setEnabled(False)
        self.btn_acc_revoke.clicked.connect(self._revoke_acceptance)
        action_row.addWidget(self.btn_acc_revoke)
        action_row.addStretch()
        layout.addLayout(action_row)

        # ── detail panel ────────────────────────────────────────────────────
        detail_grp = SectionGroupBox("Детали выбранного принятия")
        detail_layout = QVBoxLayout()
        self.acc_detail = ResultsDisplay()
        self.acc_detail.setMaximumHeight(150)
        self.acc_detail.setPlaceholderText(
            "Выберите строку, чтобы увидеть причину и срок принятия риска")
        detail_layout.addWidget(self.acc_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._acc_all: list = []          # full loaded set (rollup + view filter)
        self._acc_records: list = []      # currently displayed subset (table + CSV)
        self._acceptances_widget = w
        return w

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_acceptances(self):
        if self._acc_loading:
            return
        self._acc_loading = True
        self._set_busy(True)
        self._run_async(self._query_acc_projects, self._on_acc_loaded)

    @staticmethod
    def _query_acc_projects() -> dict:
        try:
            from core.findings_store import FindingsStore
            return {'projects': FindingsStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_acc_loaded(self, result: dict):
        self._acc_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._acc_loaded = False
            self.acc_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._acc_loaded = True

        current = self.acc_project.currentData()
        self.acc_project.blockSignals(True)
        self.acc_project.clear()
        projects = result.get('projects', [])
        for p in projects:
            self.acc_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.acc_project.findData(current)
        self.acc_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.acc_project.blockSignals(False)

        if not projects:
            self.acc_status.setText("Нет проектов с находками")
            self._populate_acc_rollup({})
            self._populate_acc_table([])
            return
        self._apply_acc_filter()

    # ── load (stage 2: per-project acceptances) ───────────────────────────────

    def _apply_acc_filter(self, *args):
        if self._acc_table_loading:
            self._acc_filter_pending = True
            return
        project = self.acc_project.currentData()
        if not project:
            self._populate_acc_rollup({})
            self._populate_acc_table([])
            self.acc_status.setText("Принято: 0")
            return
        self._acc_table_loading = True
        self._set_busy(True)
        self._run_async(lambda p=project: self._query_acc_table(p),
                        self._on_acc_table_loaded)

    @staticmethod
    def _query_acc_table(project) -> dict:
        try:
            from core.findings_store import FindingsStore
            rows = FindingsStore().risk_acceptances(project)
            return {'project': project, 'rows': rows}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_acc_table_loaded(self, result: dict):
        self._acc_table_loading = False
        self._set_busy(False)
        if self._acc_filter_pending:
            self._acc_filter_pending = False
            self._apply_acc_filter()
            return
        if result.get('error'):
            self._acc_all = []
            self._populate_acc_rollup({})
            self._populate_acc_table([])
            self.acc_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        rows = result.get('rows') or []
        self._acc_all = rows
        expired = sum(1 for r in rows
                      if (r.get('acceptance') or {}).get('expired'))
        summary = {'total': len(rows), 'active': len(rows) - expired,
                   'expired': expired}
        self.acc_status.setText(
            f"Принято: {summary['total']}  ·  действуют: {summary['active']}"
            f"  ·  истекли: {summary['expired']}")
        self._populate_acc_rollup(summary)   # rollup always spans the full set
        self._apply_acc_view()               # table honours the expired-only filter

    def _apply_acc_view(self):
        """Render the table from the full set, narrowed by the expired-only
        checkbox. Rollup counters are left untouched (they span the whole set)."""
        rows = self._acc_all
        if getattr(self, 'acc_expired_only', None) and self.acc_expired_only.isChecked():
            rows = [r for r in rows if (r.get('acceptance') or {}).get('expired')]
        self._populate_acc_table(rows)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_acc_rollup(self, summary: dict):
        for key, label in self.acc_rollup.items():
            label.setText(str(summary.get(key, 0)))

    @staticmethod
    def _render_acc_row(table, r: int, rec: dict):
        acc = rec.get('acceptance') or {}
        severity = str(rec.get('severity', '')).lower()
        until = acc.get('until') or 'бессрочно'
        status = '⚠ истекло' if acc.get('expired') else 'действует'
        values = [severity, rec.get('title', ''), acc.get('approver') or '—',
                  until, status]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 0:
                color = theme.severity_color(severity)
                if color:
                    item.setForeground(QColor(color))
            elif col == 4 and acc.get('expired'):
                item.setForeground(QColor(theme.severity_color('critical')))
            table.setItem(r, col, item)

    def _populate_acc_table(self, rows: list):
        self._acc_records = rows          # full list — selection + CSV export
        self._acc_paginator.set_rows(rows)
        self.acc_detail.clear()
        self.btn_acc_revoke.setEnabled(False)

    def _on_acc_page_changed(self):
        self.acc_detail.clear()
        self.btn_acc_revoke.setEnabled(False)

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_acc(self) -> dict:
        sel = self.acc_table.selectionModel().selectedRows()
        if not sel:
            return {}
        return self._acc_paginator.record_at(sel[0].row()) or {}

    def _on_acc_row_selected(self):
        rec = self._selected_acc()
        if not rec:
            self.btn_acc_revoke.setEnabled(False)
            return
        self.btn_acc_revoke.setEnabled(True)
        acc = rec.get('acceptance') or {}
        lines = [
            f"Находка:    {rec.get('title', '')}",
            f"Severity:   {rec.get('severity', '')}   "
            f"Категория: {rec.get('category', '')}",
            f"Статус находки: {rec.get('finding_status', '')}",
            f"Кем принят: {acc.get('approver') or '—'}   "
            f"До: {acc.get('until') or 'бессрочно'}"
            + ("   ⚠ ИСТЕКЛО" if acc.get('expired') else ""),
            f"Причина:    {acc.get('reason') or '—'}",
            f"ID находки: {rec.get('finding_id', '')}",
        ]
        self.acc_detail.setPlainText("\n".join(lines))

    # ── write: revoke the selected acceptance ─────────────────────────────────

    def _revoke_acceptance(self):
        rec = self._selected_acc()
        fid = rec.get('finding_id')
        if not fid:
            return
        self.btn_acc_revoke.setEnabled(False)
        self._set_busy(True)
        self._run_async(lambda f=fid: self._write_acc_revoke(f),
                        self._on_acc_revoked)

    @staticmethod
    def _write_acc_revoke(finding_id) -> dict:
        try:
            from core.findings_store import FindingsStore
            FindingsStore().clear_risk_acceptance(finding_id)
            return {'ok': True}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_acc_revoked(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            self.acc_status.setText(f"Ошибка: {result['error']}")
            return
        self._apply_acc_filter()          # reload so the revoked row drops off

    # ── export ────────────────────────────────────────────────────────────────

    def _export_acc_csv(self):
        from core.report_export import risk_acceptances_csv
        rows = self._acc_records
        if not rows:
            self.acc_status.setText("Нечего экспортировать")
            return
        project = self.acc_project.currentData() or 'all'
        default = f"acceptances_{project}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(risk_acceptances_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.acc_status.setText(f"Экспортировано принятий: {len(rows)}")
