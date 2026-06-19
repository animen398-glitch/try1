"""Attack Paths tab — the EPIC 11 view (Advanced Intelligence, GUI tail).

The framework's last question is "how does this connect". A lateral attack path is
a finding-bearing exposed host sharing an infrastructure node (ip / asn / netblock)
with other hosts: compromising the weak *entry* gives an attacker a *pivot* to all
co-located *targets*, some of which are high-criticality. ``core/intelligence.py``
derives these paths on read from the shared-infra clusters (asset graph), the
findings attached to their members (correlation) and the criticality ranking
(EPIC 9). This tab is the human side of that: pick a project, read the paths ranked
by score, and inspect the entry → pivot → targets chain behind each one.

Thin UI mixin folded into MainWindow, mirroring the Priorities/Criticality tabs:
every read runs off the GUI thread via ``_run_async``. Attack paths are a
display-only ranking (they never feed the risk verdict), inherently per-project,
and read-only.
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

# band → severity colour key (reuses the themed severity palette).
_BAND_SEVERITY = {'high': 'high', 'medium': 'medium', 'low': 'low'}


class AttackPathsTabMixin:
    """Builds and drives the Attack Paths tab."""

    PATH_COLUMNS = ["Score", "Band", "Entry", "Pivot", "Targets", "Critical"]

    # (summary key -> rollup-card caption), fed from
    # intelligence.build_attack_paths()['summary'] for the current project.
    PATH_ROLLUP = [
        ('paths',          'Путей'),
        ('critical_paths', 'Критичных'),
        ('top_score',      'Макс. score'),
    ]

    def _build_attack_paths_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.path_project = QComboBox()
        self.path_project.setMinimumWidth(220)
        self.path_project.currentIndexChanged.connect(self._apply_path_filter)
        ctrl.addWidget(self.path_project)

        ctrl.addStretch()
        self.path_status = QLabel("Путей: 0")
        ctrl.addWidget(self.path_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip(
            "Сохранить текущий ранжированный список путей атаки в CSV.")
        btn_export.clicked.connect(self._export_path_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_attack_paths)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (at a glance) ──────────────────────────────────────
        rollup_row = FlowLayout()
        self.path_rollup: dict = {}
        for key, title in self.PATH_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.path_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── paths table ─────────────────────────────────────────────────────
        self.path_table = QTableWidget(0, len(self.PATH_COLUMNS))
        self.path_table.setHorizontalHeaderLabels(self.PATH_COLUMNS)
        self.path_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.path_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.path_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.path_table.verticalHeader().setVisible(False)
        self.path_table.setAlternatingRowColors(True)
        header = self.path_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # pivot fills space
        self.path_table.itemSelectionChanged.connect(self._on_path_row_selected)
        layout.addWidget(self.path_table, stretch=1)

        # ── detail panel (entry → pivot → targets) ──────────────────────────
        detail_grp = SectionGroupBox("Цепочка: entry → pivot → targets")
        detail_layout = QVBoxLayout()
        self.path_detail = ResultsDisplay()
        self.path_detail.setMaximumHeight(200)
        self.path_detail.setPlaceholderText(
            "Выберите путь, чтобы увидеть точку входа, узел-pivot и цели")
        detail_layout.addWidget(self.path_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # Full ranked paths backing the table (untruncated detail on selection).
        self._path_records: list = []
        self._attack_paths_widget = w
        return w

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_attack_paths(self):
        if self._path_loading:
            return
        self._path_loading = True
        self._set_busy(True)
        self._run_async(self._query_path_projects, self._on_path_loaded)

    @staticmethod
    def _query_path_projects() -> dict:
        # Off-GUI-thread read; the store opens/uses/closes its connection here.
        try:
            from core.asset_store import AssetStore
            return {'projects': AssetStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_path_loaded(self, result: dict):
        self._path_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._attack_paths_loaded = False  # allow retry on next open/refresh
            self.path_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._attack_paths_loaded = True

        # Repopulate the project selector, preserving the current choice.
        # Attack paths are per-project (an empty project yields an empty view),
        # so — unlike Findings/Assets — there is no "all projects" entry.
        current = self.path_project.currentData()
        self.path_project.blockSignals(True)
        self.path_project.clear()
        projects = result.get('projects', [])
        for p in projects:
            self.path_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.path_project.findData(current)
        self.path_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.path_project.blockSignals(False)

        if not projects:
            self.path_status.setText("Нет проектов с активами")
            self._populate_path_rollup({})
            self._populate_path_table([])
            return
        self._apply_path_filter()

    # ── load (stage 2: per-project attack paths) ─────────────────────────────

    def _apply_path_filter(self, *args):
        if self._path_table_loading:
            self._path_filter_pending = True
            return
        project = self.path_project.currentData()
        if not project:
            self._populate_path_rollup({})
            self._populate_path_table([])
            self.path_status.setText("Путей: 0")
            return
        self._path_table_loading = True
        self._set_busy(True)
        self._run_async(
            lambda p=project: self._query_path_table(p),
            self._on_path_table_loaded,
        )

    @staticmethod
    def _query_path_table(project) -> dict:
        try:
            from core.intelligence import load_attack_paths
            return {'project': project, 'paths': load_attack_paths(project)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_path_table_loaded(self, result: dict):
        self._path_table_loading = False
        self._set_busy(False)
        if self._path_filter_pending:
            self._path_filter_pending = False
            self._apply_path_filter()
            return
        if result.get('error'):
            self.path_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        data = result.get('paths') or {}
        if data.get('error'):
            self.path_status.setText(f"Ошибка загрузки: {data['error']}")
            return
        summary = data.get('summary') or {}
        paths = data.get('paths') or []
        self.path_status.setText(
            f"Путей: {summary.get('paths', len(paths))}"
            f"  ·  критичных: {summary.get('critical_paths', 0)}")
        self._populate_path_rollup(summary)
        self._populate_path_table(paths)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_path_rollup(self, summary: dict):
        for key, label in self.path_rollup.items():
            label.setText(str(summary.get(key, 0)))

    def _populate_path_table(self, paths: list):
        self._path_records = paths
        self.path_table.setRowCount(0)
        for rec in paths:
            r = self.path_table.rowCount()
            self.path_table.insertRow(r)
            band = str(rec.get('band', '')).lower()
            pivot = f"{rec.get('pivot_type', '')} {rec.get('pivot_node', '')}".strip()
            values = [
                str(rec.get('score', '')),
                band,
                rec.get('entry', ''),
                pivot,
                str(len(rec.get('targets') or [])),
                str(rec.get('critical_targets', 0)),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 1:   # band cell — themed colour
                    color = theme.severity_color(_BAND_SEVERITY.get(band, ''))
                    if color:
                        item.setForeground(QColor(color))
                self.path_table.setItem(r, col, item)
        self.path_detail.clear()

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_path(self) -> dict:
        sel = self.path_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._path_records)):
            return {}
        return self._path_records[idx]

    def _on_path_row_selected(self):
        rec = self._selected_path()
        if rec:
            self._show_path_detail(rec)

    def _show_path_detail(self, rec: dict):
        pivot = f"{rec.get('pivot_type', '')} {rec.get('pivot_node', '')}".strip()
        targets = rec.get('targets') or []
        lines = [
            f"Score:   {rec.get('score', '')} ({rec.get('band', '')})",
            f"Entry:   {rec.get('entry', '')}  "
            f"(severity {rec.get('entry_severity', '')})",
            f"Pivot:   {pivot}  (общих хостов: {rec.get('size', '')})",
            f"Targets: {len(targets)}  "
            f"(критичных: {rec.get('critical_targets', 0)})",
        ]
        if targets:
            lines.append("Цели (pivot ведёт к):")
            for t in targets:
                lines.append(f"  • {t}")
        self.path_detail.setPlainText("\n".join(lines))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_path_csv(self):
        """Save the currently loaded ranked attack paths to a CSV file."""
        from datetime import datetime

        from core.report_export import attack_paths_csv
        rows = self._path_records
        if not rows:
            self.path_status.setText("Нечего экспортировать")
            return
        default = f"attack_paths_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(attack_paths_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.path_status.setText(f"Экспортировано путей: {len(rows)}")
