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
                        "Secrets", "High", "Medium", "Findings", "Сканов",
                        "Обновлён"]

    # (totals key -> card caption) for the estate roll-up.
    OVERVIEW_TOTALS = [
        ('projects',        'Проекты'),
        ('secrets',         'Секреты'),
        ('high',            'High'),
        ('medium',          'Medium'),
        ('active_findings', 'Активные находки'),
    ]

    # (series key -> (caption, colour)) for the per-project trend sparklines.
    OVERVIEW_TRENDS = [
        ('risk_score',     ('Risk', '#c62828')),
        ('secrets',        ('Secrets', '#6a1b9a')),
        ('attack_surface', ('Attack Surface', '#0078d4')),
    ]

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
            return pf.load_portfolio(base)
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_overview_loaded(self, result: dict):
        self._overview_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._overview_loaded = False   # allow retry on next open/refresh
            self.overview_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._overview_loaded = True

        rows = result.get('rows', [])
        self._overview_rows = rows
        self._populate_overview_totals(result.get('totals', {}))
        self._populate_overview_table(rows)
        self._render_overview_heatmap(rows)
        self._populate_overview_projects(rows)
        self.overview_status.setText(f"Проектов: {len(rows)}")

    def _populate_overview_totals(self, totals: dict):
        level = totals.get('worst_risk_level') or '—'
        color = theme.risk_color(totals.get('worst_risk_level')) or '#888'
        self.overview_risk_label.setText(f"Худший риск: {level}")
        self.overview_risk_label.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {color};")
        for key, label in self.overview_totals.items():
            label.setText(str(totals.get(key, 0)))

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
                if col in range(2, 10):
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
