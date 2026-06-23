"""Asset Criticality tab — the EPIC 9 view (Advanced Intelligence, GUI tail).

Priority (the Priorities tab) answers "which finding to fix first"; *criticality*
answers the complementary question — "which asset matters most". It is derived on
read in ``core/intelligence.py`` from the asset's type, its blast radius (assets
depending on it, from the asset graph / shared-infra clusters), the worst severity
of findings attached to it and its public exposure (takeover / reachable). This tab
is the human side of that ranking: pick a project, read assets ranked by
criticality, and inspect the named factors that drove each score.

Thin UI mixin folded into MainWindow, mirroring the Priorities/Assets tabs: every
read runs off the GUI thread via ``_run_async`` (the SQLite connection is opened
and closed inside the worker). Criticality is a display-only ranking (it never
feeds the risk verdict), inherently per-project, and read-only.
"""

from pathlib import Path

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.business_context import (
    CRITICALITY_LABELS, CRITICALITY_TIERS, DATA_SENSITIVITY, SENSITIVITY_LABELS,
    describe as describe_business, resolve as resolve_business,
)
from gui import theme
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton,
)

# criticality band → severity-ish colour key (reuses the themed severity palette so
# high/medium/low read the same as everywhere else).
_BAND_SEVERITY = {'high': 'high', 'medium': 'medium', 'low': 'low'}


class CriticalityTabMixin:
    """Builds and drives the Asset Criticality tab."""

    CRIT_COLUMNS = ["Criticality", "Band", "Тип", "Актив"]

    # (summary key -> rollup-card caption), fed from
    # intelligence.build_asset_criticality()['summary'] for the current project.
    CRIT_ROLLUP = [
        ('assets',           'Активов'),
        ('high_criticality', 'Высокая крит.'),
        ('top_criticality',  'Макс. крит.'),
    ]

    def _build_criticality_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.crit_project = QComboBox()
        self.crit_project.setMinimumWidth(220)
        self.crit_project.currentIndexChanged.connect(self._apply_crit_filter)
        ctrl.addWidget(self.crit_project)

        ctrl.addStretch()
        self.crit_status = QLabel("Активов: 0")
        ctrl.addWidget(self.crit_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip(
            "Сохранить текущий ранжированный список активов по критичности в CSV.")
        btn_export.clicked.connect(self._export_crit_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_criticality)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (at a glance) ──────────────────────────────────────
        rollup_row = FlowLayout()
        self.crit_rollup: dict = {}
        for key, title in self.CRIT_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.crit_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── criticality table ───────────────────────────────────────────────
        self.crit_table = QTableWidget(0, len(self.CRIT_COLUMNS))
        self.crit_table.setHorizontalHeaderLabels(self.CRIT_COLUMNS)
        self.crit_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.crit_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.crit_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.crit_table.verticalHeader().setVisible(False)
        self.crit_table.setAlternatingRowColors(True)
        header = self.crit_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # asset value fills space
        self.crit_table.itemSelectionChanged.connect(self._on_crit_row_selected)
        layout.addWidget(self.crit_table, stretch=1)

        # ── detail panel (factors) ──────────────────────────────────────────
        detail_grp = SectionGroupBox("Из чего критичность (факторы)")
        detail_layout = QVBoxLayout()
        self.crit_detail = ResultsDisplay()
        self.crit_detail.setMaximumHeight(180)
        self.crit_detail.setPlaceholderText(
            "Выберите актив, чтобы увидеть, из чего сложилась его критичность")
        detail_layout.addWidget(self.crit_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # ── per-asset business override editor (F1 GUI tail) ─────────────────
        # User-declared business importance for the *selected* asset; it overrides
        # the project default field-by-field and augments that asset's criticality
        # (a named factor). Keyed on the item's bare fingerprint (item['fp']) — the
        # same join key the CLI uses. Stored in metadata.json (no new table).
        asset_grp = SectionGroupBox("Бизнес-контекст актива (override выбранного)")
        asset_layout = QVBoxLayout()
        self.biz_asset_label = QLabel("Выберите актив, чтобы задать override")
        self.biz_asset_label.setWordWrap(True)
        asset_layout.addWidget(self.biz_asset_label)
        asset_row = FlowLayout()
        asset_row.addWidget(QLabel("Критичность для бизнеса:"))
        self.biz_asset_crit = self._biz_combo(CRITICALITY_TIERS, CRITICALITY_LABELS)
        asset_row.addWidget(self.biz_asset_crit)
        asset_row.addWidget(QLabel("Чувствительность данных:"))
        self.biz_asset_sens = self._biz_combo(DATA_SENSITIVITY, SENSITIVITY_LABELS)
        asset_row.addWidget(self.biz_asset_sens)
        self.biz_asset_apply = StyledButton("Применить к активу", style='secondary')
        self.biz_asset_apply.setToolTip(
            "Сохранить override бизнес-контекста для выбранного актива и "
            "пересчитать критичность с его учётом.")
        self.biz_asset_apply.clicked.connect(self._apply_business_asset)
        asset_row.addWidget(self.biz_asset_apply)
        self.biz_asset_clear = StyledButton("Сбросить override", style='secondary')
        self.biz_asset_clear.setToolTip(
            "Удалить override выбранного актива (вернуться к проектному дефолту).")
        self.biz_asset_clear.clicked.connect(self._clear_business_asset)
        asset_row.addWidget(self.biz_asset_clear)
        asset_layout.addLayout(asset_row)
        asset_grp.setLayout(asset_layout)
        layout.addWidget(asset_grp)
        self._set_biz_asset_enabled(False)

        # ── business context editor (F1 GUI) ────────────────────────────────
        # User-declared business importance for the whole project; it augments the
        # criticality scores above (a named factor) and is the fallback a per-asset
        # override layers over. Stored in metadata.json (no new table).
        biz_grp = SectionGroupBox("Бизнес-контекст проекта (влияет на критичность)")
        biz_layout = QVBoxLayout()
        biz_row = FlowLayout()
        biz_row.addWidget(QLabel("Критичность для бизнеса:"))
        self.biz_default_crit = self._biz_combo(CRITICALITY_TIERS, CRITICALITY_LABELS)
        biz_row.addWidget(self.biz_default_crit)
        biz_row.addWidget(QLabel("Чувствительность данных:"))
        self.biz_default_sens = self._biz_combo(DATA_SENSITIVITY, SENSITIVITY_LABELS)
        biz_row.addWidget(self.biz_default_sens)
        self.biz_apply = StyledButton("Применить к проекту", style='secondary')
        self.biz_apply.setToolTip(
            "Сохранить бизнес-контекст проекта в metadata.json и пересчитать "
            "критичность активов с его учётом.")
        self.biz_apply.clicked.connect(self._apply_business_default)
        biz_row.addWidget(self.biz_apply)
        biz_layout.addLayout(biz_row)
        biz_grp.setLayout(biz_layout)
        layout.addWidget(biz_grp)

        # Full ranked items backing the table (untruncated detail on selection).
        self._crit_records: list = []
        self._crit_widget = w
        return w

    @staticmethod
    def _biz_combo(options, labels) -> QComboBox:
        """A combo with a leading '—' (unset) entry plus the vocab options; the
        stored value is the option key ('' for unset)."""
        cb = QComboBox()
        cb.addItem("—", "")
        for opt in options:
            cb.addItem(labels.get(opt, opt), opt)
        return cb

    def _crit_base(self) -> str:
        return (self.settings.get('output_dir')
                or str(Path.home() / 'SiteAnalyzer'))

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_criticality(self):
        if self._crit_loading:
            return
        self._crit_loading = True
        self._set_busy(True)
        self._run_async(self._query_crit_projects, self._on_crit_loaded)

    @staticmethod
    def _query_crit_projects() -> dict:
        # Off-GUI-thread read; the store opens/uses/closes its connection here.
        try:
            from core.asset_store import AssetStore
            return {'projects': AssetStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_crit_loaded(self, result: dict):
        self._crit_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._crit_loaded = False  # allow retry on next open/refresh
            self.crit_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._crit_loaded = True

        # Repopulate the project selector, preserving the current choice.
        # Criticality is per-project (an empty project yields an empty view),
        # so — unlike Findings/Assets — there is no "all projects" entry.
        current = self.crit_project.currentData()
        self.crit_project.blockSignals(True)
        self.crit_project.clear()
        projects = result.get('projects', [])
        for p in projects:
            self.crit_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.crit_project.findData(current)
        self.crit_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.crit_project.blockSignals(False)

        if not projects:
            self.crit_status.setText("Нет проектов с активами")
            self._populate_crit_rollup({})
            self._populate_crit_table([])
            return
        self._apply_crit_filter()

    # ── load (stage 2: per-project criticality) ──────────────────────────────

    def _apply_crit_filter(self, *args):
        if self._crit_table_loading:
            self._crit_filter_pending = True
            return
        project = self.crit_project.currentData()
        if not project:
            self._populate_crit_rollup({})
            self._populate_crit_table([])
            self.crit_status.setText("Активов: 0")
            return
        self._crit_table_loading = True
        self._set_busy(True)
        base = self._crit_base()
        self._run_async(
            lambda p=project, b=base: self._query_crit_table(p, b),
            self._on_crit_table_loaded,
        )

    @staticmethod
    def _query_crit_table(project, base) -> dict:
        try:
            from core.intelligence import load_asset_criticality
            from core.project import ProjectStore
            # F1: fold in the project's business context so the criticality the tab
            # shows (and the editor presets) reflect the declared importance.
            business = None
            proj = ProjectStore(base).get(project)
            if proj is not None:
                business = proj.get_business_context()
            return {'project': project, 'business': business or {},
                    'crit': load_asset_criticality(project, business=business)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_crit_table_loaded(self, result: dict):
        self._crit_table_loading = False
        self._set_busy(False)
        if self._crit_filter_pending:
            self._crit_filter_pending = False
            self._apply_crit_filter()
            return
        if result.get('error'):
            self.crit_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        crit = result.get('crit') or {}
        if crit.get('error'):
            self.crit_status.setText(f"Ошибка загрузки: {crit['error']}")
            return
        summary = crit.get('summary') or {}
        items = crit.get('items') or []
        self._crit_business = result.get('business') or {}
        self.crit_status.setText(
            f"Активов: {summary.get('assets', len(items))}"
            f"  ·  высокая критичность: {summary.get('high_criticality', 0)}")
        self._populate_crit_rollup(summary)
        self._populate_crit_table(items)
        self._populate_biz_default(self._crit_business)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_crit_rollup(self, summary: dict):
        for key, label in self.crit_rollup.items():
            label.setText(str(summary.get(key, 0)))

    def _populate_crit_table(self, items: list):
        self._crit_records = items
        self.crit_table.setRowCount(0)
        for rec in items:
            r = self.crit_table.rowCount()
            self.crit_table.insertRow(r)
            band = str(rec.get('band', '')).lower()
            values = [
                str(rec.get('criticality', '')),
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
                self.crit_table.setItem(r, col, item)
        # Restore the previously selected asset after an apply/clear reload so the
        # editor stays on the same asset; selectRow re-fires the detail/editor fill.
        target = self._crit_reselect_fp
        self._crit_reselect_fp = None
        if target:
            for r, rec in enumerate(items):
                if rec.get('fp') == target:
                    self.crit_table.selectRow(r)
                    break
        if not self.crit_table.selectionModel().selectedRows():
            self.crit_detail.clear()
            self._populate_biz_asset(None)

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_crit(self) -> dict:
        sel = self.crit_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._crit_records)):
            return {}
        return self._crit_records[idx]

    def _on_crit_row_selected(self):
        rec = self._selected_crit()
        if rec:
            self._show_crit_detail(rec)
            self._populate_biz_asset(rec)
        else:
            self._populate_biz_asset(None)

    def _show_crit_detail(self, rec: dict):
        lines = [
            f"Актив:       {rec.get('value', '')}",
            f"Тип:         {rec.get('type', '')}",
            f"Критичность: {rec.get('criticality', '')} "
            f"({rec.get('band', '')})",
        ]
        factors = rec.get('factors') or []
        if factors:
            lines.append("Из чего критичность:")
            for f in factors:
                lines.append(f"  +{f.get('points', 0)}  {f.get('factor', '')}")
        self.crit_detail.setPlainText("\n".join(lines))

    # ── business context (F1 editor) ───────────────────────────────────────────

    @staticmethod
    def _set_combo(cb: QComboBox, value) -> None:
        idx = cb.findData(value or "")
        cb.setCurrentIndex(idx if idx >= 0 else 0)

    def _populate_biz_default(self, business: dict) -> None:
        """Reflect the project's stored default in the editor combos."""
        default = (business or {}).get('default') or {}
        self._set_combo(self.biz_default_crit, default.get('criticality'))
        self._set_combo(self.biz_default_sens, default.get('data_sensitivity'))

    def _apply_business_default(self):
        project = self.crit_project.currentData()
        if not project:
            self.crit_status.setText("Выберите проект")
            return
        crit = self.biz_default_crit.currentData() or None
        sens = self.biz_default_sens.currentData() or None
        base = self._crit_base()
        self._set_busy(True)
        self._run_async(
            lambda: self._write_business(base, project, crit, sens),
            self._on_business_written,
        )

    @staticmethod
    def _write_business(base, project, crit, sens) -> dict:
        # Off-GUI-thread write to metadata.json (full-replace of the project
        # default, mirroring business_cli / scope set semantics).
        try:
            from core.business_context import set_business_context
            from core.project import ProjectStore
            set_business_context(ProjectStore(base), project,
                                 criticality=crit, data_sensitivity=sens)
            return {'ok': True}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_business_written(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            self.crit_status.setText(f"Ошибка сохранения: {result['error']}")
            return
        self.crit_status.setText("Бизнес-контекст сохранён · пересчёт критичности…")
        self._apply_crit_filter()   # reload so criticality reflects the change

    # ── per-asset business override (F1 GUI tail) ──────────────────────────────

    def _set_biz_asset_enabled(self, on: bool) -> None:
        for w in (self.biz_asset_crit, self.biz_asset_sens,
                  self.biz_asset_apply, self.biz_asset_clear):
            w.setEnabled(on)

    def _populate_biz_asset(self, rec) -> None:
        """Reflect the selected asset's stored override in the editor combos and
        show its resolved context (project default + override)."""
        if not rec:
            self._set_combo(self.biz_asset_crit, None)
            self._set_combo(self.biz_asset_sens, None)
            self._set_biz_asset_enabled(False)
            self.biz_asset_label.setText("Выберите актив, чтобы задать override")
            return
        fp = rec.get('fp')
        override = (self._crit_business.get('assets') or {}).get(fp) or {}
        self._set_combo(self.biz_asset_crit, override.get('criticality'))
        self._set_combo(self.biz_asset_sens, override.get('data_sensitivity'))
        self._set_biz_asset_enabled(bool(fp))
        resolved = describe_business(resolve_business(self._crit_business, fp))
        self.biz_asset_label.setText(
            f"{rec.get('value', '')} — итог: {resolved or '—'}")

    def _apply_business_asset(self):
        rec = self._selected_crit()
        project = self.crit_project.currentData()
        if not rec or not rec.get('fp'):
            self.crit_status.setText("Выберите актив")
            return
        if not project:
            self.crit_status.setText("Выберите проект")
            return
        crit = self.biz_asset_crit.currentData() or None
        sens = self.biz_asset_sens.currentData() or None
        self._crit_reselect_fp = rec['fp']
        base = self._crit_base()
        self._set_busy(True)
        self._run_async(
            lambda: self._write_business_asset(base, project, rec['fp'], crit,
                                               sens, False),
            self._on_business_written,
        )

    def _clear_business_asset(self):
        rec = self._selected_crit()
        project = self.crit_project.currentData()
        if not rec or not rec.get('fp'):
            self.crit_status.setText("Выберите актив")
            return
        if not project:
            self.crit_status.setText("Выберите проект")
            return
        self._crit_reselect_fp = rec['fp']
        base = self._crit_base()
        self._set_busy(True)
        self._run_async(
            lambda: self._write_business_asset(base, project, rec['fp'], None,
                                               None, True),
            self._on_business_written,
        )

    @staticmethod
    def _write_business_asset(base, project, asset_fp, crit, sens, clear) -> dict:
        # Off-GUI-thread write of a per-asset override to metadata.json (replace
        # semantics, mirroring business_cli). ``clear`` removes the override.
        try:
            from core.business_context import (
                clear_business_context, set_business_context,
            )
            from core.project import ProjectStore
            store = ProjectStore(base)
            if clear:
                clear_business_context(store, project, asset_fp=asset_fp)
            else:
                set_business_context(store, project, asset_fp=asset_fp,
                                     criticality=crit, data_sensitivity=sens)
            return {'ok': True}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    # ── export ────────────────────────────────────────────────────────────────

    def _export_crit_csv(self):
        """Save the currently loaded ranked assets to a CSV file."""
        from datetime import datetime

        from core.report_export import criticality_csv
        rows = self._crit_records
        if not rows:
            self.crit_status.setText("Нечего экспортировать")
            return
        default = f"criticality_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(criticality_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.crit_status.setText(f"Экспортировано активов: {len(rows)}")
