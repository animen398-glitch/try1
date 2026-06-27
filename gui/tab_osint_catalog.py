"""OSINT Catalog tab — the EXT-OSINT F3 view (GUI tail).

Where the other "Управление" tabs rank findings/assets, the OSINT catalog answers
"which curated reconnaissance workflows did this scan actually exercise". It is a
pure derive-on-read guide (``core/osint_catalog.py``): a static catalog of
workflows mapped onto our existing engines, annotated per scan with coverage
(covered / partial / not run). It never scans, never touches the network, and
never feeds the risk verdict — a guide/coverage display only.

This tab is the human side: pick a project, read its latest scan's workflow
coverage, and inspect the goal + which engines ran vs are missing for each.

Report-based (like the Technology Risk / Scan Accuracy tabs — coverage needs the
scan's phase statuses), so the project list and base resolve the same way:
``ProjectStore`` over the ``output_dir`` base. Every read runs off the GUI thread
via ``_run_async``. Read-only.
"""

from pathlib import Path

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.project import ProjectStore
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton,
)

# coverage status → cell colour (covered is good = green; not run is neutral).
_STATUS_COLOR = {'covered': '#2e7d32', 'partial': '#ef6c00', 'not_run': '#999999'}
_STATUS_LABEL = {'covered': 'covered', 'partial': 'partial', 'not_run': 'not run'}


class OsintCatalogTabMixin:
    """Builds and drives the OSINT Catalog tab."""

    OSINT_COLUMNS = ["Статус", "Workflow", "Категория", "Сеть", "Покрытие"]

    # (summary key -> rollup-card caption), fed from osint_catalog.summary().
    OSINT_ROLLUP = [
        ('total',   'Воркфлоу'),
        ('covered', 'Covered'),
        ('partial', 'Partial'),
        ('not_run', 'Not run'),
    ]

    def _build_osint_catalog_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.oc_project = QComboBox()
        self.oc_project.setMinimumWidth(220)
        self.oc_project.currentIndexChanged.connect(self._apply_osint_catalog)
        ctrl.addWidget(self.oc_project)

        ctrl.addStretch()
        self.oc_status = QLabel("Воркфлоу: 0")
        ctrl.addWidget(self.oc_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip("Сохранить покрытие OSINT-воркфлоу в CSV.")
        btn_export.clicked.connect(self._export_oc_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_osint_catalog)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards ────────────────────────────────────────────────────
        rollup_row = FlowLayout()
        self.oc_rollup: dict = {}
        for key, title in self.OSINT_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.oc_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── workflows table ─────────────────────────────────────────────────
        self.oc_table = QTableWidget(0, len(self.OSINT_COLUMNS))
        self.oc_table.setHorizontalHeaderLabels(self.OSINT_COLUMNS)
        self.oc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.oc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.oc_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.oc_table.verticalHeader().setVisible(False)
        self.oc_table.setAlternatingRowColors(True)
        header = self.oc_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # workflow name fills
        self.oc_table.itemSelectionChanged.connect(self._on_oc_row_selected)
        layout.addWidget(self.oc_table, stretch=1)

        # ── detail panel (goal + engines) ───────────────────────────────────
        detail_grp = SectionGroupBox("Детали (цель + движки)")
        detail_layout = QVBoxLayout()
        self.oc_detail = ResultsDisplay()
        self.oc_detail.setMaximumHeight(200)
        self.oc_detail.setPlaceholderText(
            "Выберите воркфлоу, чтобы увидеть цель и какие движки отработали")
        detail_layout.addWidget(self.oc_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._oc_records: list = []
        self._osint_catalog_widget = w
        return w

    # ── projects base (same resolution as Technology Risk / Timeline) ──────────

    def _osint_catalog_base(self) -> str:
        return (self.settings.get('output_dir', '')
                or str(Path.home() / 'SiteAnalyzer'))

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_osint_catalog(self):
        if self._osint_loading:
            return
        self._osint_loading = True
        self._set_busy(True)
        base = self._osint_catalog_base()
        self._run_async(lambda b=base: self._query_oc_projects(b),
                        self._on_oc_loaded)

    @staticmethod
    def _query_oc_projects(base: str) -> dict:
        try:
            return {'projects': ProjectStore(base).list_projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_oc_loaded(self, result: dict):
        self._osint_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._osint_loaded = False  # allow retry on next open/refresh
            self.oc_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._osint_loaded = True

        current = self.oc_project.currentData()
        self.oc_project.blockSignals(True)
        self.oc_project.clear()
        projects = result.get('projects', [])
        for meta in projects:
            self.oc_project.addItem(
                f"{meta.get('slug', '?')} ({meta.get('scan_count', 0)})",
                meta.get('slug'))
        idx = self.oc_project.findData(current)
        self.oc_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.oc_project.blockSignals(False)

        if not projects:
            self.oc_status.setText("Нет проектов со сканами")
            self._populate_oc_rollup({})
            self._populate_oc_table([])
            return
        self._apply_osint_catalog()

    # ── load (stage 2: per-project coverage) ──────────────────────────────────

    def _apply_osint_catalog(self, *args):
        if self._osint_table_loading:
            self._osint_filter_pending = True
            return
        slug = self.oc_project.currentData()
        if not slug:
            self._populate_oc_rollup({})
            self._populate_oc_table([])
            self.oc_status.setText("Воркфлоу: 0")
            return
        self._osint_table_loading = True
        self._set_busy(True)
        base = self._osint_catalog_base()
        self._run_async(lambda b=base, s=slug: self._query_oc_table(b, s),
                        self._on_oc_table_loaded)

    @staticmethod
    def _query_oc_table(base: str, slug: str) -> dict:
        try:
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': f'проект не найден: {slug}', 'slug': slug}
            from core.osint_catalog import load_catalog
            data = load_catalog(project)
            data['slug'] = slug
            return data
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_oc_table_loaded(self, result: dict):
        self._osint_table_loading = False
        self._set_busy(False)
        if self._osint_filter_pending:
            self._osint_filter_pending = False
            self._apply_osint_catalog()
            return
        # Discard a result whose project no longer matches the selection.
        if result.get('slug') != self.oc_project.currentData():
            return
        if result.get('error'):
            self._populate_oc_rollup({})
            self._populate_oc_table([])
            self.oc_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        summary = result.get('summary') or {}
        workflows = result.get('workflows') or []
        self.oc_status.setText(
            f"Воркфлоу: {summary.get('total', len(workflows))}"
            f"  ·  covered {summary.get('covered', 0)} /"
            f" partial {summary.get('partial', 0)} /"
            f" not run {summary.get('not_run', 0)}")
        self._populate_oc_rollup(summary)
        self._populate_oc_table(workflows)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_oc_rollup(self, summary: dict):
        for key, label in self.oc_rollup.items():
            label.setText(str(summary.get(key, 0)))

    def _populate_oc_table(self, workflows: list):
        self._oc_records = workflows
        self.oc_table.setRowCount(0)
        for rec in workflows:
            r = self.oc_table.rowCount()
            self.oc_table.insertRow(r)
            status = str(rec.get('status', ''))
            engines = rec.get('engines') or []
            ran = rec.get('ran') or []
            values = [
                _STATUS_LABEL.get(status, status),
                rec.get('name', ''),
                rec.get('category', ''),
                rec.get('network', ''),
                f"{len(ran)}/{len(engines)}",
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 0:   # status cell — coverage colour
                    color = _STATUS_COLOR.get(status)
                    if color:
                        item.setForeground(QColor(color))
                self.oc_table.setItem(r, col, item)
        self.oc_detail.clear()

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_oc(self) -> dict:
        sel = self.oc_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._oc_records)):
            return {}
        return self._oc_records[idx]

    def _on_oc_row_selected(self):
        rec = self._selected_oc()
        if rec:
            self._show_oc_detail(rec)

    def _show_oc_detail(self, rec: dict):
        ran = set(rec.get('ran') or [])
        engines = rec.get('engines') or []
        engine_lines = [f"  {'✓' if e in ran else '✗'} {e}" for e in engines]
        lines = [
            f"Workflow:   {rec.get('name', '')}",
            f"Категория:  {rec.get('category', '')}",
            f"Статус:     {_STATUS_LABEL.get(rec.get('status'), rec.get('status', ''))}",
            f"Сеть:       {rec.get('network', '')}",
            f"Цель:       {rec.get('goal', '')}",
            "Движки (✓ отработал / ✗ не запускался):",
            *engine_lines,
        ]
        optional = rec.get('optional') or []
        if optional:
            opt_ran = set(rec.get('optional_ran') or [])
            lines.append("Опционально:")
            lines.extend(f"  {'✓' if e in opt_ran else '·'} {e}" for e in optional)
        produces = rec.get('produces') or []
        if produces:
            lines.append(f"Производит:  {', '.join(map(str, produces))}")
        self.oc_detail.setPlainText("\n".join(lines))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_oc_csv(self):
        """Save the currently loaded workflow coverage to a CSV file."""
        from datetime import datetime

        from core.report_export import osint_catalog_csv
        rows = self._oc_records
        if not rows:
            self.oc_status.setText("Нечего экспортировать")
            return
        default = f"osint_catalog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(osint_catalog_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.oc_status.setText(f"Экспортировано воркфлоу: {len(rows)}")
