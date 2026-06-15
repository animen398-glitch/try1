"""Assets tab — the Asset Inventory view (post-epic increment).

An asset (domain / subdomain / ip / asn / netblock / endpoint / technology) lives
across scans in ``data/assets.db`` (core/asset_store.py) with a simple lifecycle
(ACTIVE ⇄ GONE → REAPPEARED) and an event trail. This tab is the human side of
that store: pick a project, filter by type/status, read an asset's attributes +
event history. Assets are observed, not user-triaged, so — unlike Findings —
there is no status-change control; the view is read-only.

Thin UI mixin folded into MainWindow: every DB read runs off the GUI thread via
``_run_async`` (the SQLite connection is opened and closed inside the worker),
mirroring the Findings/Dashboard tabs. Status labels live in core.asset_store.
"""

from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.asset_adapter import ASSET_TYPES
from core.asset_store import STATUS_LABELS, STATUSES, AssetStore
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton,
)


class AssetsTabMixin:
    """Builds and drives the Asset Inventory tab."""

    ASSETS_COLUMNS = ["Тип", "Значение", "Статус",
                      "Перв. обнаружено", "Посл. обнаружено"]

    # (asset type -> rollup-card caption). The ASM "inventory at a glance" row;
    # one card per asset type, fed from AssetStore.summary()['by_type'] for the
    # current project filter. Order/keys mirror core.asset_adapter.ASSET_TYPES.
    ASSETS_ROLLUP = [
        ('domain',     'Домены'),
        ('subdomain',  'Субдомены'),
        ('ip',         'IP'),
        ('asn',        'ASN'),
        ('netblock',   'Netblock'),
        ('endpoint',   'Эндпоинты'),
        ('technology', 'Технологии'),
    ]

    def _build_assets_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── filter / control row ────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.assets_project = QComboBox()
        self.assets_project.setMinimumWidth(180)
        self.assets_project.currentIndexChanged.connect(self._apply_assets_filter)
        ctrl.addWidget(self.assets_project)

        ctrl.addWidget(QLabel("Тип:"))
        self.assets_type_filter = QComboBox()
        self.assets_type_filter.addItem("Все", None)
        for t in ASSET_TYPES:
            self.assets_type_filter.addItem(t, t)
        self.assets_type_filter.currentIndexChanged.connect(
            self._apply_assets_filter)
        ctrl.addWidget(self.assets_type_filter)

        ctrl.addWidget(QLabel("Статус:"))
        self.assets_status_filter = QComboBox()
        self.assets_status_filter.addItem("Все", None)
        for st in STATUSES:
            self.assets_status_filter.addItem(STATUS_LABELS.get(st, st), st)
        self.assets_status_filter.currentIndexChanged.connect(
            self._apply_assets_filter)
        ctrl.addWidget(self.assets_status_filter)

        ctrl.addStretch()
        self.assets_status = QLabel("Активных: 0 / 0")
        ctrl.addWidget(self.assets_status)
        btn_export = StyledButton("Export CSV", style='secondary')
        btn_export.setToolTip("Сохранить текущий (отфильтрованный) список активов в CSV.")
        btn_export.clicked.connect(self._export_assets_csv)
        ctrl.addWidget(btn_export)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_assets)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards (inventory at a glance) ────────────────────────────
        # Reuses the Dashboard stat-card helper; values come from the same
        # summary() the table load already fetches (no extra I/O).
        rollup_row = FlowLayout()
        self.assets_rollup: dict = {}
        for key, title in self.ASSETS_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.assets_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── assets table ────────────────────────────────────────────────────
        self.assets_table = QTableWidget(0, len(self.ASSETS_COLUMNS))
        self.assets_table.setHorizontalHeaderLabels(self.ASSETS_COLUMNS)
        self.assets_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.assets_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.assets_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.assets_table.verticalHeader().setVisible(False)
        self.assets_table.setAlternatingRowColors(True)
        header = self.assets_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # value fills space
        self.assets_table.itemSelectionChanged.connect(self._on_asset_row_selected)
        layout.addWidget(self.assets_table, stretch=1)

        # ── detail / history panel ──────────────────────────────────────────
        detail_grp = SectionGroupBox("Детали и история выбранного актива")
        detail_layout = QVBoxLayout()
        self.assets_detail = ResultsDisplay()
        self.assets_detail.setMaximumHeight(180)
        self.assets_detail.setPlaceholderText(
            "Выберите актив, чтобы увидеть атрибуты и историю событий")
        detail_layout.addWidget(self.assets_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        # Full rows backing the table, so a selection can show untruncated data.
        self._assets_records: list = []
        # F-K3: asset_id → its correlated findings (severity counts + worst),
        # filled per single-project load so the detail panel shows exposure.
        self._assets_asset_findings: dict = {}
        self._assets_widget = w
        return w

    # ── load ────────────────────────────────────────────────────────────────

    def _export_assets_csv(self):
        """Save the currently loaded (filtered) assets to a CSV file."""
        from datetime import datetime

        from core.report_export import assets_csv
        rows = self._assets_records
        if not rows:
            self.assets_status.setText("Нечего экспортировать")
            return
        default = f"assets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8-sig', newline='') as f:
                f.write(assets_csv(rows))
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить CSV: {e}")
            return
        self.assets_status.setText(f"Экспортировано активов: {len(rows)}")

    def _refresh_assets(self):
        if self._assets_loading:
            return
        self._assets_loading = True
        self._set_busy(True)
        self._run_async(self._query_assets, self._on_assets_loaded)

    @staticmethod
    def _query_assets() -> dict:
        # Off-GUI-thread read; the store opens/uses/closes its connection here.
        try:
            return {'projects': AssetStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_assets_loaded(self, result: dict):
        self._assets_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._assets_loaded = False  # allow retry on next open/refresh
            self.assets_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._assets_loaded = True

        # Repopulate the project selector, preserving the current choice.
        current = self.assets_project.currentData()
        self.assets_project.blockSignals(True)
        self.assets_project.clear()
        self.assets_project.addItem("Все проекты", None)
        for p in result.get('projects', []):
            self.assets_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.assets_project.findData(current)
        self.assets_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.assets_project.blockSignals(False)

        self._apply_assets_filter()

    # ── filter / populate ─────────────────────────────────────────────────────

    def _apply_assets_filter(self, *args):
        if self._assets_table_loading:
            self._assets_filter_pending = True
            return
        self._assets_table_loading = True
        self._set_busy(True)
        project = self.assets_project.currentData()
        atype = self.assets_type_filter.currentData()
        status = self.assets_status_filter.currentData()
        self._run_async(
            lambda p=project, t=atype, s=status: self._query_assets_table(p, t, s),
            self._on_assets_table_loaded,
        )

    @staticmethod
    def _query_assets_table(project, atype, status) -> dict:
        try:
            store = AssetStore()
            rows = store.list_assets(project=project, type=atype, status=status)
            summary = store.summary(project)
            # F-K3: correlate the project's active findings with its assets so the
            # detail panel can show each asset's findings. Uses the *unfiltered*
            # project assets for chain resolution; skipped for "all projects".
            asset_findings: dict = {}
            if project:
                try:
                    from core.correlation import build_correlation
                    from core.findings_store import FindingsStore
                    all_assets = store.list_assets(project=project)
                    findings = FindingsStore().active_findings(project)
                    asset_findings = build_correlation(
                        findings, all_assets).get('asset_findings', {})
                except Exception:   # noqa: BLE001 — correlation is best-effort
                    asset_findings = {}
            return {'rows': rows, 'summary': summary, 'project': project,
                    'asset_findings': asset_findings}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_assets_table_loaded(self, result: dict):
        self._assets_table_loading = False
        self._set_busy(False)
        if self._assets_filter_pending:
            self._assets_filter_pending = False
            self._apply_assets_filter()
            return
        if result.get('error'):
            self.assets_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        summary = result.get('summary', {})
        self.assets_status.setText(
            f"Активных: {summary.get('active', 0)} / {summary.get('total', 0)}"
            f"  ·  показано: {len(result.get('rows', []))}")
        self._assets_asset_findings = result.get('asset_findings', {})
        self._populate_assets_rollup(summary)
        self._populate_assets_table(result.get('rows', []))

    def _populate_assets_rollup(self, summary: dict):
        """Fill the inventory rollup cards from summary()['by_type']."""
        by_type = summary.get('by_type') or {}
        for key, label in self.assets_rollup.items():
            label.setText(str(by_type.get(key, 0)))

    def _populate_assets_table(self, rows: list):
        self._assets_records = rows
        self.assets_table.setRowCount(0)
        for rec in rows:
            r = self.assets_table.rowCount()
            self.assets_table.insertRow(r)
            status = rec.get('status', '')
            values = [
                rec.get('type', ''),
                rec.get('label') or rec.get('value', ''),
                STATUS_LABELS.get(status, status),
                (rec.get('first_seen_at') or '')[:10],
                (rec.get('last_seen_at') or '')[:10],
            ]
            for col, val in enumerate(values):
                self.assets_table.setItem(r, col, QTableWidgetItem(str(val)))
        self.assets_detail.clear()

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_asset(self) -> dict:
        sel = self.assets_table.selectionModel().selectedRows()
        if not sel:
            return {}
        idx = sel[0].row()
        if not (0 <= idx < len(self._assets_records)):
            return {}
        return self._assets_records[idx]

    def _on_asset_row_selected(self):
        rec = self._selected_asset()
        if not rec:
            return
        self._show_asset_detail(rec)
        # Load the event trail off the GUI thread.
        aid = rec.get('id')
        if aid:
            self._run_async(lambda a=aid: self._query_asset_events(a),
                            self._on_asset_events_loaded)

    @staticmethod
    def _query_asset_events(asset_id: str) -> dict:
        try:
            return {'id': asset_id, 'events': AssetStore().events(asset_id)}
        except Exception as e:  # noqa: BLE001
            return {'id': asset_id, 'error': str(e)}

    def _on_asset_events_loaded(self, result: dict):
        rec = self._selected_asset()
        # Discard if the selection moved on while the query ran.
        if not rec or rec.get('id') != result.get('id'):
            return
        self._show_asset_detail(rec, result.get('events'))

    def _show_asset_detail(self, rec: dict, events=None):
        status = rec.get('status', '')
        lines = [
            f"Значение:   {rec.get('label') or rec.get('value', '')}",
            f"Тип:        {rec.get('type', '')}   "
            f"Статус: {STATUS_LABELS.get(status, status)}",
            f"ID:         {rec.get('id', '')}",
            f"Обнаружено: {rec.get('first_seen_at', '')} → {rec.get('last_seen_at', '')}",
        ]
        attrs = rec.get('attrs')
        if isinstance(attrs, dict) and attrs:
            lines.append("Атрибуты:")
            for k, v in attrs.items():
                if v not in (None, ''):
                    lines.append(f"  {k}: {v}")
        # F-K3: findings correlated to this asset (exposure).
        af = (self._assets_asset_findings or {}).get(rec.get('id'))
        if af and af.get('findings'):
            counts = af.get('severity_counts', {})
            breakdown = ", ".join(f"{k}:{v}" for k, v in counts.items() if v)
            lines.append(f"Связанные находки: {len(af['findings'])} "
                         f"(worst: {af.get('worst', '—')})"
                         + (f" · {breakdown}" if breakdown else ""))
            for f in af['findings'][:8]:
                lines.append(f"  [{f.get('severity', '')}] {f.get('title', '')}")
        if events:
            lines.append("История:")
            for ev in events:
                lines.append(f"  {ev.get('at', '')}  {ev.get('type', '')}")
        self.assets_detail.setPlainText("\n".join(lines))
