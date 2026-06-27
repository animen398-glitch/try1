"""Technology Risk tab — the EPIC 15 view (Advanced Intelligence, GUI tail).

Where Scan Accuracy answers "how sure are we this detection is real", *technology
risk* answers "which detected technology or JS dependency deserves attention":
end-of-life / outdated versions and known-vulnerable libraries. ``core/tech_risk.py``
scores this as a pure display posture, derived on read from the recon phase already
in the latest scan report — it never adds scanners and never feeds the authoritative
risk verdict (vulnerable deps/CVEs are already counted via findings, EPIC 3).

This tab is the human side: pick a project, read its latest scan's technologies and
dependencies ranked by risk score (the high-band rows are what to remediate first),
and inspect the reason + evidence behind each.

Report-based (like the Scan Accuracy / Timeline tabs — it needs the scan's recon
phase, not just the stores), so the project list and base are resolved the same way:
``ProjectStore`` over the ``output_dir`` base. Every read runs off the GUI thread via
``_run_async``. Read-only; technology risk is a display measure only.
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

# risk band → severity colour key. Here a *high* band is the concerning one (unlike
# accuracy, where a low confidence is what stands out), so the mapping is direct.
_BAND_SEVERITY = {'high': 'high', 'medium': 'medium', 'low': 'low'}


class TechnologyRiskTabMixin:
    """Builds and drives the Technology Risk tab."""

    TECHRISK_COLUMNS = ["Score", "Band", "Тип", "Технология", "Причина"]

    # (summary key -> rollup-card caption), fed from
    # tech_risk.build_technology_risk()['summary'] for the current project.
    TECHRISK_ROLLUP = [
        ('items',                  'Элементов'),
        ('high',                   'Высокий риск'),
        ('vulnerable_dependencies', 'Уязвимых деп'),
    ]

    def _build_technology_risk_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.tr_project = QComboBox()
        self.tr_project.setMinimumWidth(220)
        self.tr_project.currentIndexChanged.connect(self._apply_technology_risk)
        ctrl.addWidget(self.tr_project)

        ctrl.addStretch()
        self.tr_status = QLabel("Элементов: 0")
        ctrl.addWidget(self.tr_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip(
            "Сохранить текущий список технологий с риск-оценкой в CSV.")
        btn_export.clicked.connect(self._export_tr_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_technology_risk)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (at a glance) ──────────────────────────────────────
        rollup_row = FlowLayout()
        self.tr_rollup: dict = {}
        for key, title in self.TECHRISK_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.tr_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── items table (risk-desc) ─────────────────────────────────────────
        self.tr_table = QTableWidget(0, len(self.TECHRISK_COLUMNS))
        self.tr_table.setHorizontalHeaderLabels(self.TECHRISK_COLUMNS)
        self.tr_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tr_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tr_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tr_table.verticalHeader().setVisible(False)
        self.tr_table.setAlternatingRowColors(True)
        header = self.tr_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # reason fills space
        self.tr_table.itemSelectionChanged.connect(self._on_tr_row_selected)
        layout.addWidget(self.tr_table, stretch=1)

        # ── detail panel (reason + evidence) ────────────────────────────────
        detail_grp = SectionGroupBox("Детали (причина + доказательства)")
        detail_layout = QVBoxLayout()
        self.tr_detail = ResultsDisplay()
        self.tr_detail.setMaximumHeight(200)
        self.tr_detail.setPlaceholderText(
            "Выберите технологию, чтобы увидеть причину риска и доказательства "
            "детекта")
        detail_layout.addWidget(self.tr_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._tr_records: list = []
        self._technology_risk_widget = w
        return w

    # ── projects base (same resolution as Scan Accuracy / Timeline) ────────────

    def _technology_risk_base(self) -> str:
        return (self.settings.get('output_dir', '')
                or str(Path.home() / 'SiteAnalyzer'))

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_technology_risk(self):
        if self._tr_loading:
            return
        self._tr_loading = True
        self._set_busy(True)
        base = self._technology_risk_base()
        self._run_async(lambda b=base: self._query_tr_projects(b),
                        self._on_tr_loaded)

    @staticmethod
    def _query_tr_projects(base: str) -> dict:
        try:
            return {'projects': ProjectStore(base).list_projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_tr_loaded(self, result: dict):
        self._tr_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._tr_loaded = False  # allow retry on next open/refresh
            self.tr_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._tr_loaded = True

        current = self.tr_project.currentData()
        self.tr_project.blockSignals(True)
        self.tr_project.clear()
        projects = result.get('projects', [])
        for meta in projects:
            self.tr_project.addItem(
                f"{meta.get('slug', '?')} ({meta.get('scan_count', 0)})",
                meta.get('slug'))
        idx = self.tr_project.findData(current)
        self.tr_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.tr_project.blockSignals(False)

        if not projects:
            self.tr_status.setText("Нет проектов со сканами")
            self._populate_tr_rollup({})
            self._populate_tr_table([])
            return
        self._apply_technology_risk()

    # ── load (stage 2: per-project technology risk) ──────────────────────────

    def _apply_technology_risk(self, *args):
        if self._tr_table_loading:
            self._tr_filter_pending = True
            return
        slug = self.tr_project.currentData()
        if not slug:
            self._populate_tr_rollup({})
            self._populate_tr_table([])
            self.tr_status.setText("Элементов: 0")
            return
        self._tr_table_loading = True
        self._set_busy(True)
        base = self._technology_risk_base()
        self._run_async(lambda b=base, s=slug: self._query_tr_table(b, s),
                        self._on_tr_table_loaded)

    @staticmethod
    def _query_tr_table(base: str, slug: str) -> dict:
        try:
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': f'проект не найден: {slug}', 'slug': slug}
            from core.tech_risk import load_technology_risk
            data = load_technology_risk(project)
            data['slug'] = slug
            return data
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_tr_table_loaded(self, result: dict):
        self._tr_table_loading = False
        self._set_busy(False)
        if self._tr_filter_pending:
            self._tr_filter_pending = False
            self._apply_technology_risk()
            return
        # Discard a result whose project no longer matches the selection.
        if result.get('slug') != self.tr_project.currentData():
            return
        if result.get('error'):
            self._populate_tr_rollup({})
            self._populate_tr_table([])
            self.tr_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        summary = result.get('summary') or {}
        items = result.get('items') or []
        self.tr_status.setText(
            f"Элементов: {summary.get('items', len(items))}"
            f"  ·  риск: {summary.get('score', 0)} ({summary.get('band', 'clean')})")
        self._populate_tr_rollup(summary)
        self._populate_tr_table(items)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_tr_rollup(self, summary: dict):
        for key, label in self.tr_rollup.items():
            label.setText(str(summary.get(key, 0)))

    def _populate_tr_table(self, items: list):
        self._tr_records = items
        self.tr_table.setRowCount(0)
        for rec in items:
            r = self.tr_table.rowCount()
            self.tr_table.insertRow(r)
            band = str(rec.get('band', '')).lower()
            name = str(rec.get('name', '')).strip()
            version = str(rec.get('version', '')).strip()
            values = [
                str(rec.get('score', '')),
                band,
                rec.get('kind', ''),
                f"{name} {version}".strip(),
                rec.get('reason', ''),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 1:   # band cell — themed colour (high band = attention)
                    color = theme.severity_color(_BAND_SEVERITY.get(band, ''))
                    if color:
                        item.setForeground(QColor(color))
                self.tr_table.setItem(r, col, item)
        self.tr_detail.clear()

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_tr(self) -> dict:
        sel = self.tr_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._tr_records)):
            return {}
        return self._tr_records[idx]

    def _on_tr_row_selected(self):
        rec = self._selected_tr()
        if rec:
            self._show_tr_detail(rec)

    def _show_tr_detail(self, rec: dict):
        name = str(rec.get('name', '')).strip()
        version = str(rec.get('version', '')).strip()
        lines = [
            f"Технология:  {f'{name} {version}'.strip()}",
            f"Тип:         {rec.get('kind', '')}",
            f"Категория:   {rec.get('category', '')}",
            f"Риск:        {rec.get('score', '')} ({rec.get('band', '')})",
            f"Причина:     {rec.get('reason', '')}",
        ]
        evidence = rec.get('evidence') or []
        if evidence:
            lines.append("Доказательства:")
            for ev in evidence:
                lines.append(f"  • {ev}")
        self.tr_detail.setPlainText("\n".join(lines))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_tr_csv(self):
        """Save the currently loaded technology-risk list to a CSV file."""
        from datetime import datetime

        from core.report_export import technology_risk_csv
        rows = self._tr_records
        if not rows:
            self.tr_status.setText("Нечего экспортировать")
            return
        default = f"technology_risk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(technology_risk_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.tr_status.setText(f"Экспортировано элементов: {len(rows)}")
