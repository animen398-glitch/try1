"""Scan Accuracy tab — the MODULE 1 view (Advanced Intelligence, GUI tail).

Criticality answers "which asset matters", priority "what to fix first"; *accuracy*
answers "how sure are we this detection is real". ``core/intelligence.py`` scores a
unified **confidence** for every scanned entity (findings / technologies / CVEs /
assets / infrastructure / API endpoints / secrets), derived on read from the
corroboration, validation and detection-method signals each already carries. This
tab is the human side of that: pick a project, read its latest scan's detections
ranked by confidence (the low-confidence ones are what a triager should verify),
and inspect the evidence + factors behind each score.

Report-based (like the Timeline tab — accuracy needs the scan's phases, not just
the stores), so the project list and base are resolved the same way: ``ProjectStore``
over the ``output_dir`` base. Every read runs off the GUI thread via ``_run_async``.
Accuracy is a display-only measure of detection trust — it never feeds the risk
verdict — and the view is read-only.
"""

from pathlib import Path

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.project import ProjectStore
from gui import theme
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton,
)

# confidence band → severity colour key (reuses the themed palette: high = strong,
# low = the attention colour, so the rows that need double-checking stand out).
_BAND_SEVERITY = {'high': 'low', 'medium': 'medium', 'low': 'high'}


class AccuracyTabMixin:
    """Builds and drives the Scan Accuracy tab."""

    ACCURACY_COLUMNS = ["Confidence", "Band", "Тип", "Сущность", "Проверка"]

    # (summary key -> rollup-card caption), fed from
    # intelligence.build_accuracy()['summary'] for the current project.
    ACCURACY_ROLLUP = [
        ('entities',        'Сущностей'),
        ('high_confidence', 'Высокая увер.'),
        ('avg_confidence',  'Средняя увер.'),
    ]

    def _build_accuracy_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.acc_project = QComboBox()
        self.acc_project.setMinimumWidth(220)
        self.acc_project.currentIndexChanged.connect(self._apply_accuracy)
        ctrl.addWidget(self.acc_project)

        ctrl.addStretch()
        self.acc_status = QLabel("Сущностей: 0")
        ctrl.addWidget(self.acc_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip(
            "Сохранить текущий список сущностей с уверенностью детекта в CSV.")
        btn_export.clicked.connect(self._export_acc_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_accuracy)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (at a glance) ──────────────────────────────────────
        rollup_row = FlowLayout()
        self.acc_rollup: dict = {}
        for key, title in self.ACCURACY_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.acc_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── entities table (confidence-desc) ────────────────────────────────
        self.acc_table = QTableWidget(0, len(self.ACCURACY_COLUMNS))
        self.acc_table.setHorizontalHeaderLabels(self.ACCURACY_COLUMNS)
        self.acc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.acc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.acc_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.acc_table.verticalHeader().setVisible(False)
        self.acc_table.setAlternatingRowColors(True)
        header = self.acc_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # entity fills space
        self.acc_table.itemSelectionChanged.connect(self._on_acc_row_selected)
        layout.addWidget(self.acc_table, stretch=1)

        # ── detail panel (evidence + factors) ───────────────────────────────
        detail_grp = SectionGroupBox(
            "Из чего уверенность (доказательства + факторы)")
        detail_layout = QVBoxLayout()
        self.acc_detail = ResultsDisplay()
        self.acc_detail.setMaximumHeight(200)
        self.acc_detail.setPlaceholderText(
            "Выберите сущность, чтобы увидеть доказательства детекта и из чего "
            "сложилась уверенность")
        detail_layout.addWidget(self.acc_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._acc_records: list = []
        self._accuracy_widget = w
        return w

    # ── projects base (same resolution as Timeline / Scan Diff) ────────────────

    def _accuracy_base(self) -> str:
        return (self.settings.get('output_dir', '')
                or str(Path.home() / 'SiteAnalyzer'))

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_accuracy(self):
        if self._acc_loading:
            return
        self._acc_loading = True
        self._set_busy(True)
        base = self._accuracy_base()
        self._run_async(lambda b=base: self._query_acc_projects(b),
                        self._on_acc_loaded)

    @staticmethod
    def _query_acc_projects(base: str) -> dict:
        try:
            return {'projects': ProjectStore(base).list_projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_acc_loaded(self, result: dict):
        self._acc_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._acc_loaded = False  # allow retry on next open/refresh
            self.acc_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._acc_loaded = True

        current = self.acc_project.currentData()
        self.acc_project.blockSignals(True)
        self.acc_project.clear()
        projects = result.get('projects', [])
        for meta in projects:
            self.acc_project.addItem(
                f"{meta.get('slug', '?')} ({meta.get('scan_count', 0)})",
                meta.get('slug'))
        idx = self.acc_project.findData(current)
        self.acc_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.acc_project.blockSignals(False)

        if not projects:
            self.acc_status.setText("Нет проектов со сканами")
            self._populate_acc_rollup({})
            self._populate_acc_table([])
            return
        self._apply_accuracy()

    # ── load (stage 2: per-project accuracy) ─────────────────────────────────

    def _apply_accuracy(self, *args):
        if self._acc_table_loading:
            self._acc_filter_pending = True
            return
        slug = self.acc_project.currentData()
        if not slug:
            self._populate_acc_rollup({})
            self._populate_acc_table([])
            self.acc_status.setText("Сущностей: 0")
            return
        self._acc_table_loading = True
        self._set_busy(True)
        base = self._accuracy_base()
        self._run_async(lambda b=base, s=slug: self._query_acc_table(b, s),
                        self._on_acc_table_loaded)

    @staticmethod
    def _query_acc_table(base: str, slug: str) -> dict:
        try:
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': f'проект не найден: {slug}', 'slug': slug}
            from core.intelligence import load_accuracy
            data = load_accuracy(project)
            data['slug'] = slug
            return data
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_acc_table_loaded(self, result: dict):
        self._acc_table_loading = False
        self._set_busy(False)
        if self._acc_filter_pending:
            self._acc_filter_pending = False
            self._apply_accuracy()
            return
        # Discard a result whose project no longer matches the selection.
        if result.get('slug') != self.acc_project.currentData():
            return
        if result.get('error'):
            self.acc_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        summary = result.get('summary') or {}
        items = result.get('items') or []
        self.acc_status.setText(
            f"Сущностей: {summary.get('entities', len(items))}"
            f"  ·  средняя уверенность: {summary.get('avg_confidence', 0)}%")
        self._populate_acc_rollup(summary)
        self._populate_acc_table(items)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_acc_rollup(self, summary: dict):
        for key, label in self.acc_rollup.items():
            val = summary.get(key, 0)
            label.setText(f"{val}%" if key == 'avg_confidence' else str(val))

    def _populate_acc_table(self, items: list):
        self._acc_records = items
        self.acc_table.setRowCount(0)
        for rec in items:
            r = self.acc_table.rowCount()
            self.acc_table.insertRow(r)
            band = str(rec.get('band', '')).lower()
            values = [
                f"{rec.get('score', '')}%",
                band,
                rec.get('entity_type', ''),
                rec.get('label', ''),
                rec.get('verification', ''),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 1:   # band cell — themed colour (low band = attention)
                    color = theme.severity_color(_BAND_SEVERITY.get(band, ''))
                    if color:
                        item.setForeground(QColor(color))
                self.acc_table.setItem(r, col, item)
        self.acc_detail.clear()

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_acc(self) -> dict:
        sel = self.acc_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._acc_records)):
            return {}
        return self._acc_records[idx]

    def _on_acc_row_selected(self):
        rec = self._selected_acc()
        if rec:
            self._show_acc_detail(rec)

    def _show_acc_detail(self, rec: dict):
        lines = [
            f"Сущность:    {rec.get('label', '')}",
            f"Тип:         {rec.get('entity_type', '')}",
            f"Уверенность: {rec.get('score', '')}% ({rec.get('band', '')})",
            f"Проверка:    {rec.get('verification', '')}",
        ]
        source = rec.get('source') or []
        if source:
            lines.append(f"Источник:    {', '.join(str(s) for s in source)}")
        evidence = rec.get('evidence') or []
        if evidence:
            lines.append("Доказательства:")
            for ev in evidence:
                lines.append(f"  • {ev}")
        factors = rec.get('factors') or []
        if factors:
            lines.append("Из чего уверенность:")
            for f in factors:
                lines.append(f"  +{f.get('points', 0)}  {f.get('factor', '')}")
        self.acc_detail.setPlainText("\n".join(lines))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_acc_csv(self):
        """Save the currently loaded accuracy list to a CSV file."""
        from datetime import datetime

        from core.report_export import accuracy_csv
        rows = self._acc_records
        if not rows:
            self.acc_status.setText("Нечего экспортировать")
            return
        default = f"accuracy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(accuracy_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.acc_status.setText(f"Экспортировано сущностей: {len(rows)}")
