"""Overview tab — Executive Dashboard across the whole project estate (F5).

The portfolio counterpart of the per-project tabs: it reads every project's
``metadata.json`` (latest risk / attack-surface / secrets / findings) plus the
F1 active-findings count and shows them three ways —

  * **totals** — estate roll-up cards (projects, worst risk, secrets, …);
  * **portfolio table** — one row per project, worst risk first, with the risk
    delta vs the previous scan;
  * **exposure heatmap** — projects × {Secrets, SourceMap, Cookie, GraphQL,
    High, Medium, Surface, Findings} (broken down by detection engine);
  * **trends** — per-project risk / secrets / attack-surface sparklines.

Thin UI mixin folded into MainWindow (architectural invariant I1/I4): all
aggregation lives in ``core.portfolio`` / ``core.timeline`` and all drawing in
``core.dashboard_charts`` (offline stdlib SVG → ``QSvgWidget``, no new runtime
dependency). Both the portfolio and a project's series are loaded off the GUI
thread via ``_run_async``, mirroring the Findings/Timeline tabs. The projects
base is resolved the same way (settings ``output_dir`` → ``~/SiteAnalyzer``).
"""

from pathlib import Path

from qtpy.QtCore import QByteArray, Qt
from qtpy.QtGui import QColor
try:                                       # QSvgWidget: Qt6 home is QtSvgWidgets,
    from qtpy.QtSvgWidgets import QSvgWidget   # Qt5 keeps it in QtSvg (qtpy won't
except ImportError:                            # backfill QtSvgWidgets on PyQt5).
    from qtpy.QtSvg import QSvgWidget
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QScrollArea, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from core import dashboard_charts as dc
from core import portfolio as pf
from core.project import ProjectStore
from core.timeline import build_series
from gui import theme
from gui.ui_components import SectionGroupBox, StyledButton


class OverviewTabMixin:
    """Builds and drives the Executive Overview tab."""

    OVERVIEW_COLUMNS = ["Проект", "Риск", "Score", "Δ", "Surface",
                        "Secrets", "High", "Medium", "Warnings", "Findings", "Сканов",
                        "Обновлён"]

    # Company roll-up table (F-C3) — one row per company over its projects.
    OVERVIEW_COMPANY_COLUMNS = ["Компания", "Проектов", "Риск", "Score",
                                "Secrets", "High", "Medium", "Warnings", "Findings",
                                "Активы"]

    # (totals key -> card caption) for the estate roll-up.
    OVERVIEW_TOTALS = [
        ('projects',        'Проекты'),
        ('secrets',         'Секреты'),
        ('high',            'High'),
        ('medium',          'Medium'),
        ('warning_count',   'Warnings'),
        ('active_findings', 'Активные находки'),
    ]

    # Mission Center portfolio cards (derive-on-read, core.mission_overview).
    OVERVIEW_MISSION_CARDS = [
        ('total',         'Миссии'),
        ('ready',         'Ready'),
        ('running',       'Running'),
        ('completed',     'Completed'),
        ('failed',        'Failed'),
        ('client_facing', 'Client-facing'),
    ]

    # (series key -> (caption, colour)) for the per-project trend sparklines.
    OVERVIEW_TRENDS = [
        ('risk_score',     ('Risk', '#c62828')),
        ('secrets',        ('Secrets', '#6a1b9a')),
        ('attack_surface', ('Attack Surface', '#0078d4')),
    ]

    @staticmethod
    def _warning_tooltip(summary: list) -> str:
        lines = []
        for item in summary or []:
            if not isinstance(item, dict):
                continue
            stage = item.get('stage') or 'pipeline'
            message = item.get('message') or item.get('error') or 'warning'
            error = item.get('error')
            lines.append(f"{stage}: {message}" + (f" ({error})" if error else ""))
        return "\n".join(lines)

    def _build_overview_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        self.overview_risk_label = QLabel("Худший риск: —")
        self.overview_risk_label.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #888;")
        ctrl.addWidget(self.overview_risk_label)
        ctrl.addStretch()
        self.overview_status = QLabel("Проектов: 0")
        ctrl.addWidget(self.overview_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip("Сохранить портфолио проектов в CSV.")
        btn_export.clicked.connect(self._export_overview_csv)
        ctrl.addWidget(btn_export)
        btn_export_proj = StyledButton("Export project…", style='secondary')
        btn_export_proj.setToolTip(
            "Экспортировать выбранный проект (дерево + findings/assets) в .zip "
            "для переноса на другую машину или шаринга.")
        btn_export_proj.clicked.connect(self._export_project_bundle)
        ctrl.addWidget(btn_export_proj)
        btn_import_proj = StyledButton("Import project…", style='secondary')
        btn_import_proj.setToolTip("Импортировать проект из .zip-бандла.")
        btn_import_proj.clicked.connect(self._import_project_bundle)
        ctrl.addWidget(btn_import_proj)
        btn_prune = StyledButton("Prune old scans", style='secondary')
        btn_prune.setToolTip(
            "Удалить артефакты старых сканов выбранного проекта по политике "
            "retention (индекс и история сохраняются — тренд не пострадает).")
        btn_prune.clicked.connect(self._prune_project_scans)
        ctrl.addWidget(btn_prune)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_overview)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # Estate roll-up cards (reuses the Dashboard's stat-card helper).
        totals_row = QHBoxLayout()
        self.overview_totals: dict = {}
        for key, title in self.OVERVIEW_TOTALS:
            card, value_label = self._make_stat_card(title)
            self.overview_totals[key] = value_label
            totals_row.addWidget(card)
        layout.addLayout(totals_row)

        # Mission Center portfolio roll-up (M7) — derive-on-read, read-only.
        mission_grp = SectionGroupBox("Миссии (Mission Center)")
        mission_v = QVBoxLayout()
        mission_row = QHBoxLayout()
        self.overview_mission_cards: dict = {}
        for key, title in self.OVERVIEW_MISSION_CARDS:
            card, value_label = self._make_stat_card(title)
            self.overview_mission_cards[key] = value_label
            mission_row.addWidget(card)
        mission_v.addLayout(mission_row)
        self.overview_mission_recent = QLabel("Последняя миссия: —")
        mission_v.addWidget(self.overview_mission_recent)
        mission_grp.setLayout(mission_v)
        layout.addWidget(mission_grp)

        # Companies roll-up (F-C3) — group the estate by company; selecting a
        # company filters the projects table below to its projects.
        comp_grp = SectionGroupBox("Компании (сводка по проектам)")
        comp_v = QVBoxLayout()
        self.overview_companies_table = QTableWidget(
            0, len(self.OVERVIEW_COMPANY_COLUMNS))
        self.overview_companies_table.setHorizontalHeaderLabels(
            self.OVERVIEW_COMPANY_COLUMNS)
        self.overview_companies_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers)
        self.overview_companies_table.setSelectionBehavior(
            QAbstractItemView.SelectRows)
        self.overview_companies_table.setSelectionMode(
            QAbstractItemView.SingleSelection)
        self.overview_companies_table.verticalHeader().setVisible(False)
        self.overview_companies_table.setAlternatingRowColors(True)
        ch = self.overview_companies_table.horizontalHeader()
        ch.setSectionResizeMode(QHeaderView.ResizeToContents)
        ch.setSectionResizeMode(0, QHeaderView.Stretch)
        self.overview_companies_table.itemSelectionChanged.connect(
            self._on_company_row_selected)
        comp_v.addWidget(self.overview_companies_table)
        filt_row = QHBoxLayout()
        self.overview_company_filter_label = QLabel("Фильтр проектов: все")
        filt_row.addWidget(self.overview_company_filter_label)
        filt_row.addStretch()
        btn_clear = StyledButton("Показать все", style='secondary')
        btn_clear.setToolTip("Снять фильтр по компании с таблицы проектов.")
        btn_clear.clicked.connect(self._clear_company_filter)
        filt_row.addWidget(btn_clear)
        comp_v.addLayout(filt_row)
        comp_grp.setLayout(comp_v)
        layout.addWidget(comp_grp, stretch=1)

        # Portfolio table — one row per project, worst risk first.
        table_grp = SectionGroupBox("Проекты (худший риск сверху)")
        table_v = QVBoxLayout()
        self.overview_table = QTableWidget(0, len(self.OVERVIEW_COLUMNS))
        self.overview_table.setHorizontalHeaderLabels(self.OVERVIEW_COLUMNS)
        self.overview_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.overview_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.overview_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.overview_table.verticalHeader().setVisible(False)
        self.overview_table.setAlternatingRowColors(True)
        header = self.overview_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(0, QHeaderView.Stretch)   # project fills space
        # Selecting a project drives the trend sparklines below.
        self.overview_table.itemSelectionChanged.connect(self._on_overview_row_selected)
        table_v.addWidget(self.overview_table)
        # Assign the selected project to a company (F-C3). Editable combo so a
        # new company can be typed (created on assign) or picked from existing.
        assign_row = QHBoxLayout()
        assign_row.addWidget(QLabel("Компания выбранного проекта:"))
        self.overview_assign_company = QComboBox()
        self.overview_assign_company.setEditable(True)
        self.overview_assign_company.setMinimumWidth(200)
        self.overview_assign_company.setToolTip(
            "Выберите проект в таблице, укажите/выберите компанию и нажмите "
            "«Назначить». Пустое поле снимает принадлежность.")
        assign_row.addWidget(self.overview_assign_company)
        btn_assign = StyledButton("Назначить", style='secondary')
        btn_assign.clicked.connect(self._assign_company)
        assign_row.addWidget(btn_assign)
        assign_row.addStretch()
        table_v.addLayout(assign_row)
        table_grp.setLayout(table_v)
        layout.addWidget(table_grp, stretch=2)

        # Exposure heatmap.
        heat_grp = SectionGroupBox("Карта рисков (проекты × категории)")
        heat_v = QVBoxLayout()
        self.overview_heatmap = QSvgWidget()
        self.overview_heatmap.setMinimumHeight(60)
        heat_v.addWidget(self.overview_heatmap)
        heat_grp.setLayout(heat_v)
        layout.addWidget(heat_grp, stretch=1)

        # Per-project trend sparklines.
        trend_grp = SectionGroupBox("Тренды выбранного проекта")
        trend_outer = QVBoxLayout()
        sel_row = QHBoxLayout()
        sel_row.addWidget(QLabel("Проект:"))
        self.overview_trend_project = QComboBox()
        self.overview_trend_project.setMinimumWidth(220)
        self.overview_trend_project.currentIndexChanged.connect(self._apply_overview_trend)
        sel_row.addWidget(self.overview_trend_project)
        sel_row.addStretch()
        # Attack-surface graph of the selected project's latest scan (reuses the
        # offline graph from core.attack_surface — rendered in a dialog).
        btn_graph = StyledButton("Граф атак-поверхности", style='secondary')
        btn_graph.clicked.connect(self._open_overview_graph)
        sel_row.addWidget(btn_graph)
        trend_outer.addLayout(sel_row)

        spark_row = QHBoxLayout()
        self.overview_sparklines: dict = {}
        for key, (caption, _color) in self.OVERVIEW_TRENDS:
            box = SectionGroupBox(caption)
            box_v = QVBoxLayout()
            spark = QSvgWidget()
            spark.setMinimumHeight(56)
            self.overview_sparklines[key] = spark
            box_v.addWidget(spark)
            box.setLayout(box_v)
            spark_row.addWidget(box)
        trend_outer.addLayout(spark_row)
        trend_grp.setLayout(trend_outer)
        layout.addWidget(trend_grp, stretch=1)

        # Portfolio rows backing the table/heatmap (for selection → trend).
        self._overview_rows: list = []
        # Company roll-up rows + the active company filter (set of project slugs
        # or None for "all") backing the projects-table filter (F-C3).
        self._overview_companies: list = []
        self._overview_company_filter = None
        self._overview_widget = w
        return w

    # ── projects base (same resolution as Timeline / Scan Diff) ─────────────────

    def _overview_base(self) -> str:
        return (self.settings.get('output_dir', '')
                or str(Path.home() / 'SiteAnalyzer'))

    @staticmethod
    def _set_svg(widget: QSvgWidget, svg: str) -> None:
        widget.load(QByteArray(svg.encode('utf-8')))

    # ── load: the whole portfolio ───────────────────────────────────────────────

    def _export_overview_csv(self):
        """Save the current project portfolio to a CSV file."""
        from datetime import datetime

        from core.report_export import portfolio_csv
        rows = self._overview_rows
        if not rows:
            self.overview_status.setText("Нечего экспортировать")
            return
        default = f"portfolio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(portfolio_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.overview_status.setText(f"Экспортировано проектов: {len(rows)}")

    # ── project bundle export / import (core.project_io) ──────────────────────────

    def _export_project_bundle(self):
        """Export the selected portfolio project to a portable .zip (off-thread)."""
        slug = self._selected_overview_slug()
        if not slug:
            self.overview_status.setText("Выберите проект в таблице для экспорта")
            return
        default = f"{slug}.zip"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export project", default, "Project bundle (*.zip)")
        if not path:
            return
        base = self._overview_base()
        self._set_busy(True)
        self._run_async(
            lambda b=base, s=slug, p=path: self._do_export_bundle(b, s, p),
            self._on_bundle_exported)

    @staticmethod
    def _do_export_bundle(base: str, slug: str, path: str) -> dict:
        try:
            from core.project_io import export_project
            return export_project(base, slug, path)
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_bundle_exported(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            QMessageBox.critical(self, "Ошибка экспорта", result['error'])
            return
        self.overview_status.setText(
            f"Экспортирован {result['slug']}: {result['findings']} findings, "
            f"{result['assets']} assets, {result['scans']} сканов")

    # ── scan retention ──────────────────────────────────────────────────────────

    def _prune_project_scans(self):
        """Prune the selected project's old scan artifact dirs per the configured
        retention policy (index + history kept). Confirms before deleting."""
        slug = self._selected_overview_slug()
        if not slug:
            self.overview_status.setText("Выберите проект в таблице для прореживания")
            return
        from core.retention import plan_retention, policy_from_settings
        pol = policy_from_settings()
        keep_last = pol['keep_last'] or None
        keep_days = pol['keep_days'] or None
        if keep_last is None and keep_days is None:
            self.overview_status.setText(
                "Задайте retention.keep_last / keep_days в настройках")
            return
        base = self._overview_base()
        project = ProjectStore(base).get(slug)
        if project is None:
            self.overview_status.setText("Проект не найден")
            return
        plan = plan_retention(project, keep_last=keep_last, keep_days=keep_days)
        n = len(plan['prune'])
        if n == 0:
            self.overview_status.setText("Нет старых сканов для прореживания")
            return
        if QMessageBox.question(
                self, "Prune old scans",
                f"Удалить артефакты {n} старых сканов проекта «{slug}»?\n"
                "Индекс и история сохранятся — тренд не пострадает."
        ) != QMessageBox.Yes:
            return
        self._set_busy(True)
        self._run_async(
            lambda b=base, s=slug, pl=plan: self._do_prune_scans(b, s, pl),
            self._on_scans_pruned)

    @staticmethod
    def _do_prune_scans(base: str, slug: str, plan: dict) -> dict:
        try:
            from core.retention import apply_retention
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': 'project not found'}
            return apply_retention(project, plan)
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_scans_pruned(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            QMessageBox.critical(self, "Ошибка", result['error'])
            return
        mb = (result.get('freed_bytes', 0)) // (1024 * 1024)
        self.overview_status.setText(
            f"Прорежено сканов: {len(result.get('pruned', []))}, "
            f"освобождено ~{mb} МБ")

    def _import_project_bundle(self):
        """Import a project from a .zip bundle (off-thread), then refresh."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import project", "", "Project bundle (*.zip)")
        if not path:
            return
        from core.project_io import bundle_info
        info = bundle_info(path)
        if info is None:
            QMessageBox.critical(self, "Ошибка", "Это не бандл проекта (.zip).")
            return
        base = self._overview_base()
        slug = info.get('slug', '?')
        # Pre-flight: warn + offer overwrite when the project already exists.
        replace = False
        if (ProjectStore(base).root / slug).exists():
            choice = QMessageBox.question(
                self, "Проект существует",
                f"Проект «{slug}» уже есть. Перезаписать его данными из бандла?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if choice != QMessageBox.Yes:
                return
            replace = True
        self._set_busy(True)
        self._run_async(
            lambda b=base, p=path, r=replace: self._do_import_bundle(b, p, r),
            self._on_bundle_imported)

    @staticmethod
    def _do_import_bundle(base: str, path: str, replace: bool) -> dict:
        try:
            from core.project_io import import_project
            return import_project(path, base, replace=replace)
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_bundle_imported(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            QMessageBox.critical(self, "Ошибка импорта", result['error'])
            return
        if result.get('skipped'):
            self.overview_status.setText(
                f"Пропущено ({result.get('reason')}): {result.get('slug')}")
            return
        self.overview_status.setText(
            f"Импортирован {result['slug']}: {result['findings']} findings, "
            f"{result['assets']} assets, {result['files']} файлов")
        self._refresh_overview()

    def _refresh_overview(self):
        if self._overview_loading:
            return
        self._overview_loading = True
        self._set_busy(True)
        base = self._overview_base()
        self._run_async(lambda b=base: self._query_overview(b),
                        self._on_overview_loaded)

    @staticmethod
    def _query_overview(base: str) -> dict:
        try:
            data = pf.load_portfolio(base)
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}
        try:
            from core.mission_overview import build_mission_overview
            data['missions_overview'] = build_mission_overview()
        except Exception:  # noqa: BLE001 — overview must render even if missions fail
            data['missions_overview'] = {'total': 0, 'counts': {},
                                         'client_facing': 0, 'missions': []}
        return data

    def _on_overview_loaded(self, result: dict):
        self._overview_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._overview_loaded = False   # allow retry on next open/refresh
            self._overview_rows = []
            self._overview_companies = []
            self._overview_company_filter = None
            self._populate_overview_totals({})
            self._populate_overview_table([])
            self._render_overview_heatmap([])
            self._populate_overview_projects([])
            self._populate_overview_companies([])
            self._populate_assign_combo([])
            self._populate_overview_missions({})
            self.overview_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._overview_loaded = True

        rows = result.get('rows', [])
        self._overview_rows = rows
        self._populate_overview_totals(result.get('totals', {}))
        self._populate_overview_missions(result.get('missions_overview', {}))
        self._populate_overview_table(rows)
        self._apply_company_filter()              # re-apply any active filter
        self._render_overview_heatmap(rows)
        self._populate_overview_projects(rows)
        self.overview_status.setText(f"Проектов: {len(rows)}")
        self._load_overview_companies()           # F-C3 company roll-up

    def _populate_overview_totals(self, totals: dict):
        level = totals.get('worst_risk_level') or '—'
        color = theme.risk_color(totals.get('worst_risk_level')) or '#888'
        self.overview_risk_label.setText(f"Худший риск: {level}")
        self.overview_risk_label.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {color};")
        for key, label in self.overview_totals.items():
            label.setText(str(totals.get(key, 0)))

    def _populate_overview_missions(self, mo: dict):
        counts = mo.get('counts') or {}
        values = {
            'total': mo.get('total', 0),
            'client_facing': mo.get('client_facing', 0),
            'ready': counts.get('ready', 0),
            'running': counts.get('running', 0),
            'completed': counts.get('completed', 0),
            'failed': counts.get('failed', 0),
        }
        for key, label in self.overview_mission_cards.items():
            label.setText(str(values.get(key, 0)))
        missions = mo.get('missions') or []
        if not missions:
            self.overview_mission_recent.setText("Последняя миссия: —")
            return
        m = missions[0]
        recent = (f"Последняя миссия: {m.get('objective') or m.get('mission_id')}"
                  f" — {m.get('status')}")
        if m.get('last_run_status'):
            recent += (f" (run {m.get('last_run_id')}: {m.get('last_run_status')},"
                       f" client-facing {m.get('client_facing', 0)})")
        self.overview_mission_recent.setText(recent)

    def _populate_overview_table(self, rows: list):
        self.overview_table.setRowCount(0)
        for row in rows:
            r = self.overview_table.rowCount()
            self.overview_table.insertRow(r)
            level = row.get('risk_level') or '—'
            delta = row.get('risk_delta')
            delta_text = '—' if delta is None else (
                f"+{delta:g}" if delta > 0 else f"{delta:g}")
            values = [
                row.get('slug', ''),
                level,
                _str_or_dash(row.get('risk_score')),
                delta_text,
                _str_or_dash(row.get('attack_surface')),
                row.get('secrets', 0),
                row.get('high', 0),
                row.get('medium', 0),
                row.get('warning_count', 0),
                row.get('active_findings', 0),
                row.get('scan_count', 0),
                (row.get('updated_at') or '')[:19].replace('T', ' '),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 1:                       # risk level → coloured
                    rc = theme.risk_color(level)
                    if rc:
                        item.setForeground(QColor(rc))
                elif col == 3 and delta is not None and delta != 0:
                    item.setForeground(QColor('#c62828' if delta > 0 else '#2e7d32'))
                elif col == 8:
                    tip = self._warning_tooltip(row.get('warning_summary') or [])
                    if tip:
                        item.setToolTip(tip)
                if col in range(2, 11):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.overview_table.setItem(r, col, item)

    def _render_overview_heatmap(self, rows: list):
        from gui import theme
        matrix = pf.build_exposure_matrix(rows)
        ch = theme.chrome()      # theme-aware label/header colours (F6 T6.4)
        svg = dc.heatmap(matrix['row_labels'], matrix['col_labels'],
                         matrix['cells'], label_color=ch['chart_label'],
                         header_color=ch['chart_header'])
        self._set_svg(self.overview_heatmap, svg)

    def _populate_overview_projects(self, rows: list):
        current = self.overview_trend_project.currentData()
        self.overview_trend_project.blockSignals(True)
        self.overview_trend_project.clear()
        for row in rows:
            slug = row.get('slug')
            self.overview_trend_project.addItem(
                f"{slug} ({row.get('scan_count', 0)})", slug)
        idx = self.overview_trend_project.findData(current)
        if idx >= 0:
            self.overview_trend_project.setCurrentIndex(idx)
        self.overview_trend_project.blockSignals(False)
        self._apply_overview_trend()

    def _on_overview_row_selected(self):
        rows = self.overview_table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if not (0 <= idx < len(self._overview_rows)):
            return
        slug = self._overview_rows[idx].get('slug')
        combo_idx = self.overview_trend_project.findData(slug)
        if combo_idx >= 0 and self.overview_trend_project.currentIndex() != combo_idx:
            self.overview_trend_project.setCurrentIndex(combo_idx)

    def _selected_overview_slug(self):
        """Slug of the project selected in the portfolio table, or None."""
        sel = self.overview_table.selectionModel().selectedRows()
        if not sel:
            return None
        idx = sel[0].row()
        if not (0 <= idx < len(self._overview_rows)):
            return None
        return self._overview_rows[idx].get('slug')

    # ── F-C3: company roll-up + filter + assignment ──────────────────────────────

    def _load_overview_companies(self):
        """Fire the company roll-up query (chained after the portfolio load)."""
        if self._overview_companies_loading:
            return
        self._overview_companies_loading = True
        base = self._overview_base()
        self._run_async(lambda b=base: self._query_companies(b),
                        self._on_companies_loaded)

    @staticmethod
    def _query_companies(base: str) -> dict:
        try:
            from core.company import load_company_view
            return load_company_view(base)
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_companies_loaded(self, result: dict):
        self._overview_companies_loading = False
        if result.get('error'):
            self.overview_status.setText(f"Ошибка компаний: {result['error']}")
            return
        rows = result.get('rows', [])
        self._overview_companies = rows
        self._populate_overview_companies(rows)
        self._populate_assign_combo(rows)

    def _populate_overview_companies(self, rows: list):
        from core.company import UNASSIGNED
        self.overview_companies_table.setRowCount(0)
        for row in rows:
            r = self.overview_companies_table.rowCount()
            self.overview_companies_table.insertRow(r)
            level = row.get('risk_level') or '—'
            values = [
                row.get('name') or row.get('slug', ''),
                row.get('project_count', 0),
                level,
                _str_or_dash(row.get('risk_score')),
                row.get('secrets', 0),
                row.get('high', 0),
                row.get('medium', 0),
                row.get('warning_count', 0),
                row.get('active_findings', 0),
                row.get('asset_total', 0),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 2 and row.get('slug') != UNASSIGNED:
                    rc = theme.risk_color(level)
                    if rc:
                        item.setForeground(QColor(rc))
                if col in range(1, 10):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.overview_companies_table.setItem(r, col, item)

    def _populate_assign_combo(self, rows: list):
        """Fill the editable company combo with existing company names."""
        from core.company import UNASSIGNED
        current = self.overview_assign_company.currentText()
        self.overview_assign_company.blockSignals(True)
        self.overview_assign_company.clear()
        self.overview_assign_company.addItem("")          # "" = unassign
        for row in rows:
            if row.get('slug') != UNASSIGNED:
                self.overview_assign_company.addItem(row.get('name') or row['slug'])
        self.overview_assign_company.setEditText(current)
        self.overview_assign_company.blockSignals(False)

    def _on_company_row_selected(self):
        sel = self.overview_companies_table.selectionModel().selectedRows()
        if not sel:
            return
        idx = sel[0].row()
        if not (0 <= idx < len(self._overview_companies)):
            return
        company = self._overview_companies[idx]
        self._overview_company_filter = set(company.get('project_slugs') or [])
        self.overview_company_filter_label.setText(
            f"Фильтр проектов: {company.get('name') or company.get('slug', '')}")
        self._apply_company_filter()

    def _clear_company_filter(self):
        self._overview_company_filter = None
        self.overview_companies_table.clearSelection()
        self.overview_company_filter_label.setText("Фильтр проектов: все")
        self._apply_company_filter()

    def _apply_company_filter(self):
        """Show only the filtered company's projects in the portfolio table."""
        keep = self._overview_company_filter
        for r in range(self.overview_table.rowCount()):
            item = self.overview_table.item(r, 0)
            slug = item.text() if item else ''
            self.overview_table.setRowHidden(r, keep is not None and slug not in keep)

    def _assign_company(self):
        slug = self._selected_overview_slug()
        if not slug:
            self.overview_status.setText("Выберите проект в таблице для назначения")
            return
        if self._overview_assign_loading:
            return
        self._overview_assign_loading = True
        self._set_busy(True)
        base = self._overview_base()
        name = self.overview_assign_company.currentText().strip()
        self._run_async(lambda b=base, s=slug, n=name: self._do_assign(b, s, n),
                        self._on_assign_done)

    @staticmethod
    def _do_assign(base: str, slug: str, name: str) -> dict:
        """Assign (or, with an empty name, clear) a project's company off-thread.

        A non-empty name is registered (idempotent) and its slug stored on the
        project; an empty name unassigns. Read-modify-write, never crashes UI."""
        try:
            from core.company import CompanyRegistry
            from core.project import ProjectStore
            cslug = CompanyRegistry().create(name) if name else None
            ok = ProjectStore(base).assign(slug, cslug)
            return {'ok': ok, 'slug': slug, 'name': name}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_assign_done(self, result: dict):
        self._overview_assign_loading = False
        self._set_busy(False)
        if result.get('error'):
            self.overview_status.setText(f"Ошибка назначения: {result['error']}")
            return
        if not result.get('ok'):
            self.overview_status.setText(f"Проект не найден: {result.get('slug', '')}")
            return
        target = result.get('name') or 'Unassigned'
        self.overview_status.setText(
            f"Проект {result.get('slug', '')} → {target}")
        self._refresh_overview()              # reload portfolio + companies

    # ── load: one project's metric series (for the sparklines) ───────────────────

    def _apply_overview_trend(self, *args):
        slug = self.overview_trend_project.currentData()
        if not slug:
            for spark in self.overview_sparklines.values():
                self._set_svg(spark, dc.sparkline([]))
            return
        if self._overview_series_loading:
            self._overview_series_pending = True
            return
        self._overview_series_loading = True
        self._set_busy(True)
        base = self._overview_base()
        self._run_async(lambda b=base, s=slug: self._query_overview_series(b, s),
                        self._on_overview_series_loaded)

    @staticmethod
    def _query_overview_series(base: str, slug: str) -> dict:
        try:
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': f'проект не найден: {slug}', 'slug': slug}
            # build_series reads only metadata.json scans[] — cheap, no reports.
            return {'slug': slug, 'series': build_series(project.scans())}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_overview_series_loaded(self, result: dict):
        self._overview_series_loading = False
        self._set_busy(False)
        if self._overview_series_pending:
            self._overview_series_pending = False
            self._apply_overview_trend()
            return
        # Discard a result whose project no longer matches the selection.
        if result.get('slug') != self.overview_trend_project.currentData():
            return
        if result.get('error'):
            self.overview_status.setText(f"Ошибка трендов: {result['error']}")
            return
        series = result.get('series', [])
        for key, (_caption, color) in self.OVERVIEW_TRENDS:
            values = [p.get(key) for p in series]
            self._set_svg(self.overview_sparklines[key],
                          dc.sparkline(values, color=color))

    # ── attack-surface graph (latest scan of the selected project) ───────────────

    def _open_overview_graph(self):
        slug = self.overview_trend_project.currentData()
        if not slug:
            self.overview_status.setText("Выберите проект для графа")
            return
        if self._overview_graph_loading:
            return
        self._overview_graph_loading = True
        self._set_busy(True)
        base = self._overview_base()
        self._run_async(lambda b=base, s=slug: self._query_overview_graph(b, s),
                        self._on_overview_graph_loaded)

    @staticmethod
    def _query_overview_graph(base: str, slug: str) -> dict:
        """Build the latest scan's attack-surface SVG (off-thread, read-only).

        Reuses ``core.attack_surface`` — no new graph logic. ``render_svg`` omits
        the XML namespace (fine for inline HTML), so it is injected here for the
        standalone ``QSvgRenderer``."""
        try:
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': f'проект не найден: {slug}', 'slug': slug}
            latest = project.latest_scan() or {}
            report = (project.load_scan_report(latest['id'])
                      if latest.get('id') else None)
            if not report:
                return {'slug': slug, 'svg': None}
            from core.attack_surface import build_surface, render_svg
            svg = render_svg(build_surface(report))
            if not svg.lstrip().startswith('<svg'):
                return {'slug': slug, 'svg': None}      # not enough data
            if 'xmlns' not in svg:
                svg = svg.replace('<svg ',
                                  '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
            return {'slug': slug, 'svg': svg}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_overview_graph_loaded(self, result: dict):
        self._overview_graph_loading = False
        self._set_busy(False)
        if result.get('error'):
            self.overview_status.setText(f"Ошибка графа: {result['error']}")
            return
        slug = result.get('slug', '')
        svg = result.get('svg')
        if not svg:
            self.overview_status.setText(f"Нет данных для графа: {slug}")
            return
        self._show_graph_dialog(slug, svg)

    def _show_graph_dialog(self, slug: str, svg: str):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Attack Surface — {slug}")
        dlg.resize(820, 520)
        v = QVBoxLayout(dlg)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        view = QSvgWidget()
        self._set_svg(view, svg)
        size = view.renderer().defaultSize()
        if size.isValid():
            view.setMinimumSize(size)
        scroll.setWidget(view)
        v.addWidget(scroll)
        dlg.exec()


def _str_or_dash(value) -> str:
    return '—' if value is None else str(value)
