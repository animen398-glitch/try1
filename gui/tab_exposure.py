"""Asset Exposure tab — the likelihood-axis view (Advanced Intelligence, GUI tail).

Asset Criticality answers "which asset matters most" (impact); *exposure* answers
the complementary question — "which asset is most reachable / attackable right now"
(likelihood). It is derived on read in ``core/intelligence.py`` from the asset's
reachability (takeover candidate / public 2xx / merely resolved), the open findings
attached to it (correlation) and its blast radius (assets depending on it / its
share of a co-hosted cluster) — deliberately WITHOUT the asset-type weight, so a
reachable low-value subdomain with a fresh vuln is "hot" even though the asset itself
is cheap. This tab is the human side of that ranking: pick a project, read assets
ranked by exposure, and inspect the named factors that drove each score.

Thin UI mixin folded into MainWindow, mirroring the Criticality/Assets tabs: every
read runs off the GUI thread via ``_run_async`` (the SQLite connection is opened and
closed inside the worker). Exposure is a display-only ranking (it never feeds the
risk verdict), inherently per-project, and read-only.
"""

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from gui import theme
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton, TablePaginator,
)

# exposure band → severity-ish colour key (reuses the themed severity palette so
# high/medium/low read the same as everywhere else).
_BAND_SEVERITY = {'high': 'high', 'medium': 'medium', 'low': 'low'}


class ExposureTabMixin:
    """Builds and drives the Asset Exposure tab."""

    EXP_COLUMNS = ["Exposure", "Band", "Тип", "Актив"]

    # (summary key -> rollup-card caption), fed from
    # intelligence.build_exposure()['summary'] for the current project.
    EXP_ROLLUP = [
        ('assets',         'Активов'),
        ('exposed_assets', 'Высокая эксп.'),
        ('top_exposure',   'Макс. эксп.'),
    ]

    def _build_exposure_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.exp_project = QComboBox()
        self.exp_project.setMinimumWidth(220)
        self.exp_project.currentIndexChanged.connect(self._apply_exp_filter)
        ctrl.addWidget(self.exp_project)

        ctrl.addStretch()
        self.exp_status = QLabel("Активов: 0")
        ctrl.addWidget(self.exp_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip(
            "Сохранить текущий ранжированный список активов по экспозиции в CSV.")
        btn_export.clicked.connect(self._export_exp_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_exposure)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (at a glance) ──────────────────────────────────────
        rollup_row = FlowLayout()
        self.exp_rollup: dict = {}
        for key, title in self.EXP_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.exp_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── exposure table ──────────────────────────────────────────────────
        self.exp_table = QTableWidget(0, len(self.EXP_COLUMNS))
        self.exp_table.setHorizontalHeaderLabels(self.EXP_COLUMNS)
        self.exp_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.exp_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.exp_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.exp_table.verticalHeader().setVisible(False)
        self.exp_table.setAlternatingRowColors(True)
        header = self.exp_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # asset value fills space
        self.exp_table.itemSelectionChanged.connect(self._on_exp_row_selected)
        layout.addWidget(self.exp_table, stretch=1)
        # Page the per-asset exposure list so a large inventory never freezes the
        # widget; the full list stays in _exp_records for selection.
        self._exp_paginator = TablePaginator(
            self.exp_table, self._render_exp_row,
            on_page_changed=lambda: self.exp_detail.clear())
        layout.addWidget(self._exp_paginator.widget)

        # ── detail panel (factors) ──────────────────────────────────────────
        detail_grp = SectionGroupBox("Из чего экспозиция (факторы)")
        detail_layout = QVBoxLayout()
        self.exp_detail = ResultsDisplay()
        self.exp_detail.setMaximumHeight(180)
        self.exp_detail.setPlaceholderText(
            "Выберите актив, чтобы увидеть, из чего сложилась его экспозиция")
        detail_layout.addWidget(self.exp_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # Full ranked items backing the table (untruncated detail on selection).
        self._exp_records: list = []
        self._exp_widget = w
        return w

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_exposure(self):
        if self._exp_loading:
            return
        self._exp_loading = True
        self._set_busy(True)
        self._run_async(self._query_exp_projects, self._on_exp_loaded)

    @staticmethod
    def _query_exp_projects() -> dict:
        # Off-GUI-thread read; the store opens/uses/closes its connection here.
        try:
            from core.asset_store import AssetStore
            return {'projects': AssetStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_exp_loaded(self, result: dict):
        self._exp_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._exp_loaded = False  # allow retry on next open/refresh
            self.exp_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._exp_loaded = True

        # Repopulate the project selector, preserving the current choice.
        # Exposure is per-project (an empty project yields an empty view), so —
        # unlike Findings/Assets — there is no "all projects" entry.
        current = self.exp_project.currentData()
        self.exp_project.blockSignals(True)
        self.exp_project.clear()
        projects = result.get('projects', [])
        for p in projects:
            self.exp_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.exp_project.findData(current)
        self.exp_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.exp_project.blockSignals(False)

        if not projects:
            self.exp_status.setText("Нет проектов с активами")
            self._populate_exp_rollup({})
            self._populate_exp_table([])
            return
        self._apply_exp_filter()

    # ── load (stage 2: per-project exposure) ──────────────────────────────────

    def _apply_exp_filter(self, *args):
        if self._exp_table_loading:
            self._exp_filter_pending = True
            return
        project = self.exp_project.currentData()
        if not project:
            self._populate_exp_rollup({})
            self._populate_exp_table([])
            self.exp_status.setText("Активов: 0")
            return
        self._exp_table_loading = True
        self._set_busy(True)
        self._run_async(
            lambda p=project: self._query_exp_table(p),
            self._on_exp_table_loaded,
        )

    @staticmethod
    def _query_exp_table(project) -> dict:
        try:
            from core.intelligence import load_exposure
            return {'project': project, 'exp': load_exposure(project)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_exp_table_loaded(self, result: dict):
        self._exp_table_loading = False
        self._set_busy(False)
        if self._exp_filter_pending:
            self._exp_filter_pending = False
            self._apply_exp_filter()
            return
        if result.get('error'):
            self._populate_exp_rollup({})
            self._populate_exp_table([])
            self.exp_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        exp = result.get('exp') or {}
        if exp.get('error'):
            self._populate_exp_rollup({})
            self._populate_exp_table([])
            self.exp_status.setText(f"Ошибка загрузки: {exp['error']}")
            return
        summary = exp.get('summary') or {}
        items = exp.get('items') or []
        self.exp_status.setText(
            f"Активов: {summary.get('assets', len(items))}"
            f"  ·  высокая экспозиция: {summary.get('exposed_assets', 0)}")
        self._populate_exp_rollup(summary)
        self._populate_exp_table(items)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_exp_rollup(self, summary: dict):
        for key, label in self.exp_rollup.items():
            label.setText(str(summary.get(key, 0)))

    def _populate_exp_table(self, items: list):
        self._exp_records = items
        self._exp_paginator.set_rows(items)
        self.exp_detail.clear()

    def _render_exp_row(self, table, r, rec):
        band = str(rec.get('band', '')).lower()
        values = [
            str(rec.get('exposure', '')),
            band,
            rec.get('type', ''),
            rec.get('value', ''),
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 1:   # band cell — themed colour
                color = theme.severity_color(_BAND_SEVERITY.get(band, ''))
                if color:
                    item.setForeground(QColor(color))
            table.setItem(r, col, item)

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_exp(self) -> dict:
        sel = self.exp_table.selectionModel().selectedRows()
        if not sel:
            return {}
        return self._exp_paginator.record_at(sel[0].row()) or {}

    def _on_exp_row_selected(self):
        rec = self._selected_exp()
        if rec:
            self._show_exp_detail(rec)

    def _show_exp_detail(self, rec: dict):
        lines = [
            f"Актив:     {rec.get('value', '')}",
            f"Тип:       {rec.get('type', '')}",
            f"Экспозиция: {rec.get('exposure', '')} "
            f"({rec.get('band', '')})",
        ]
        factors = rec.get('factors') or []
        if factors:
            lines.append("Из чего экспозиция:")
            for f in factors:
                lines.append(f"  +{f.get('points', 0)}  {f.get('factor', '')}")
        self.exp_detail.setPlainText("\n".join(lines))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_exp_csv(self):
        """Save the currently loaded ranked assets to a CSV file."""
        from datetime import datetime

        from core.report_export import exposure_csv
        rows = self._exp_records
        if not rows:
            self.exp_status.setText("Нечего экспортировать")
            return
        default = f"exposure_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(exposure_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.exp_status.setText(f"Экспортировано активов: {len(rows)}")
