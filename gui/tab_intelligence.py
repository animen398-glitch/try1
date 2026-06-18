"""Priorities tab — the Core Intelligence view (Epic 7, GUI tail).

The platform detects well; ``core/intelligence.py`` adds the *judgement* on top,
fully derived on read: each active finding gets a **confidence** (how sure we are
it is real), a **priority** (what to fix first — severity discounted by confidence,
amplified by exposure / SLA urgency) and an **explanation** (why it matters). This
tab is the human side of that: pick a project, read findings ranked by priority,
and inspect the named factors that drove each score (so the number is auditable).

Thin UI mixin folded into MainWindow, mirroring the Findings/Assets tabs: every
read runs off the GUI thread via ``_run_async`` (the SQLite connection is opened
and closed inside the worker). Intelligence is inherently per-project (like the
Timeline/Correlation views), so the project selector lists real projects only and
the view is read-only — priorities are derived, not user-triaged.
"""

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from gui import theme
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton,
)


class IntelligenceTabMixin:
    """Builds and drives the Priorities (Core Intelligence) tab."""

    INTEL_COLUMNS = ["Priority", "Confidence", "Severity", "Категория", "Заголовок"]

    # (summary key -> rollup-card caption). The "at a glance" row, fed from
    # intelligence.build_intelligence()['summary'] for the current project.
    INTEL_ROLLUP = [
        ('findings',       'Находок'),
        ('high_confidence', 'Высокая увер.'),
        ('top_priority',   'Макс. priority'),
    ]

    def _build_intelligence_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.intel_project = QComboBox()
        self.intel_project.setMinimumWidth(220)
        self.intel_project.currentIndexChanged.connect(self._apply_intel_filter)
        ctrl.addWidget(self.intel_project)

        ctrl.addStretch()
        self.intel_status = QLabel("Находок: 0")
        ctrl.addWidget(self.intel_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip(
            "Сохранить текущий ранжированный список приоритетов в CSV.")
        btn_export.clicked.connect(self._export_intel_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_intelligence)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (at a glance) ──────────────────────────────────────
        rollup_row = FlowLayout()
        self.intel_rollup: dict = {}
        for key, title in self.INTEL_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.intel_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── priorities table ────────────────────────────────────────────────
        self.intel_table = QTableWidget(0, len(self.INTEL_COLUMNS))
        self.intel_table.setHorizontalHeaderLabels(self.INTEL_COLUMNS)
        self.intel_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.intel_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.intel_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.intel_table.verticalHeader().setVisible(False)
        self.intel_table.setAlternatingRowColors(True)
        header = self.intel_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # title fills space
        self.intel_table.itemSelectionChanged.connect(self._on_intel_row_selected)
        layout.addWidget(self.intel_table, stretch=1)

        # ── detail panel (explanation + factors) ────────────────────────────
        detail_grp = SectionGroupBox(
            "Почему этот приоритет (объяснение + факторы)")
        detail_layout = QVBoxLayout()
        self.intel_detail = ResultsDisplay()
        self.intel_detail.setMaximumHeight(200)
        self.intel_detail.setPlaceholderText(
            "Выберите находку, чтобы увидеть объяснение и из чего сложились "
            "confidence и priority")
        detail_layout.addWidget(self.intel_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # Full ranked items backing the table (untruncated detail on selection).
        self._intel_records: list = []
        self._intel_widget = w
        return w

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_intelligence(self):
        if self._intel_loading:
            return
        self._intel_loading = True
        self._set_busy(True)
        self._run_async(self._query_intel_projects, self._on_intel_loaded)

    @staticmethod
    def _query_intel_projects() -> dict:
        # Off-GUI-thread read; the store opens/uses/closes its connection here.
        try:
            from core.findings_store import FindingsStore
            return {'projects': FindingsStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_intel_loaded(self, result: dict):
        self._intel_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._intel_loaded = False  # allow retry on next open/refresh
            self.intel_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._intel_loaded = True

        # Repopulate the project selector, preserving the current choice.
        # Intelligence is per-project (an empty project yields an empty view),
        # so — unlike Findings/Assets — there is no "all projects" entry.
        current = self.intel_project.currentData()
        self.intel_project.blockSignals(True)
        self.intel_project.clear()
        projects = result.get('projects', [])
        for p in projects:
            self.intel_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.intel_project.findData(current)
        self.intel_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.intel_project.blockSignals(False)

        if not projects:
            self.intel_status.setText("Нет проектов с находками")
            self._populate_intel_rollup({})
            self._populate_intel_table([])
            return
        self._apply_intel_filter()

    # ── load (stage 2: per-project intelligence) ─────────────────────────────

    def _apply_intel_filter(self, *args):
        if self._intel_table_loading:
            self._intel_filter_pending = True
            return
        project = self.intel_project.currentData()
        if not project:
            self._populate_intel_rollup({})
            self._populate_intel_table([])
            self.intel_status.setText("Находок: 0")
            return
        self._intel_table_loading = True
        self._set_busy(True)
        self._run_async(
            lambda p=project: self._query_intel_table(p),
            self._on_intel_table_loaded,
        )

    @staticmethod
    def _query_intel_table(project) -> dict:
        try:
            from core.intelligence import load_intelligence
            return {'project': project, 'intel': load_intelligence(project)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_intel_table_loaded(self, result: dict):
        self._intel_table_loading = False
        self._set_busy(False)
        if self._intel_filter_pending:
            self._intel_filter_pending = False
            self._apply_intel_filter()
            return
        if result.get('error'):
            self.intel_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        intel = result.get('intel') or {}
        if intel.get('error'):
            self.intel_status.setText(f"Ошибка загрузки: {intel['error']}")
            return
        summary = intel.get('summary') or {}
        items = intel.get('items') or []
        self.intel_status.setText(
            f"Находок: {summary.get('findings', len(items))}"
            f"  ·  высокая уверенность: {summary.get('high_confidence', 0)}")
        self._populate_intel_rollup(summary)
        self._populate_intel_table(items)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_intel_rollup(self, summary: dict):
        for key, label in self.intel_rollup.items():
            label.setText(str(summary.get(key, 0)))

    def _populate_intel_table(self, items: list):
        self._intel_records = items
        self.intel_table.setRowCount(0)
        for rec in items:
            r = self.intel_table.rowCount()
            self.intel_table.insertRow(r)
            severity = str(rec.get('severity', '')).lower()
            values = [
                str(rec.get('priority', '')),
                f"{rec.get('confidence', '')}% ({rec.get('confidence_band', '')})",
                severity,
                rec.get('category', ''),
                rec.get('title', ''),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 2:   # severity cell — themed colour
                    color = theme.severity_color(severity)
                    if color:
                        item.setForeground(QColor(color))
                self.intel_table.setItem(r, col, item)
        self.intel_detail.clear()

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_intel(self) -> dict:
        sel = self.intel_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._intel_records)):
            return {}
        return self._intel_records[idx]

    def _on_intel_row_selected(self):
        rec = self._selected_intel()
        if rec:
            self._show_intel_detail(rec)

    def _show_intel_detail(self, rec: dict):
        lines = [
            f"Заголовок:  {rec.get('title', '')}",
            f"Категория:  {rec.get('category', '')}   "
            f"Severity: {rec.get('severity', '')}",
            f"Priority:   {rec.get('priority', '')}   "
            f"Confidence: {rec.get('confidence', '')}% "
            f"({rec.get('confidence_band', '')})",
        ]
        info = rec.get('explanation') or {}
        if info:
            lines += [
                f"Описание:    {info.get('description', '')}",
                f"Воздействие: {info.get('impact', '')}",
                f"Remediation: {info.get('remediation', '')}",
            ]
        prio_factors = rec.get('priority_factors') or []
        if prio_factors:
            lines.append("Из чего priority:")
            for f in prio_factors:
                lines.append(f"  +{f.get('points', 0)}  {f.get('factor', '')}")
        conf_factors = rec.get('confidence_factors') or []
        if conf_factors:
            lines.append("Из чего confidence:")
            for f in conf_factors:
                lines.append(f"  +{f.get('points', 0)}  {f.get('factor', '')}")
        self.intel_detail.setPlainText("\n".join(lines))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_intel_csv(self):
        """Save the currently loaded ranked priorities to a CSV file."""
        from datetime import datetime

        from core.report_export import intelligence_csv
        rows = self._intel_records
        if not rows:
            self.intel_status.setText("Нечего экспортировать")
            return
        default = f"priorities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(intelligence_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.intel_status.setText(f"Экспортировано приоритетов: {len(rows)}")
