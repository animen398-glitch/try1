"""Timeline tab — the project's history feed + metric series (roadmap F2, T2.3).

Reads a project's timeline (derived on the fly by core.timeline — no extra store)
and shows it two ways: a chronological change feed (new secret / risk ↑ / finding
resolved …) and a per-scan metric table (the data provider for future charts).

Thin UI mixin folded into MainWindow: the project list and the timeline are both
built off the GUI thread via ``_run_async`` (disk + findings DB), mirroring the
Findings/Dashboard tabs. The projects base is resolved the same way Scan Diff
does it (settings ``output_dir`` → ``~/SiteAnalyzer``).
"""

from pathlib import Path

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.project import ProjectStore
from gui import theme                            # one severity palette, shared
from gui.ui_components import SectionGroupBox, StyledButton

# Event type → RU label for the feed.
_EVENT_LABELS = {
    'new_secret':          'Новый секрет',
    'new_secret_generic':  'Новый секрет (generic)',
    'takeover':            'Takeover',
    'new_subdomain':       'Новый субдомен',
    'new_technology':      'Новая технология',
    'tech_version_change': 'Смена версии',
    'cert_change':         'Смена сертификата',
    'cert_expiring':       'Сертификат истекает',
    'cert_expired':        'Сертификат истёк',
    'new_endpoint':        'Новый эндпоинт',
    'new_historical_url':  'Новый историч. URL',
    'new_graphql':         'Новый GraphQL',
    'graphql_introspection': 'GraphQL introspection',
    'new_sourcemap':       'Утёкший source map',
    'weak_cookie':         'Слабая cookie',
    'cookie_weakened':     'Cookie ослаблена',
    'new_vulnerable_dependency': 'Уязвимая зависимость',
    'dependency_vulnerable':     'Зависимость стала уязвимой',
    'security_header_removed':   'Security-заголовок убран',
    'risk_increase':       'Риск ↑',
    'risk_decrease':       'Риск ↓',
    'new_finding':         'Новая находка',
    'finding_resolved':    'Находка исправлена',
    'finding_reopened':    'Находка переоткрыта',
    'new_asset':           'Новый актив',
    'asset_reappeared':    'Актив вернулся',
    'asset_gone':          'Актив исчез',
    'sla_breach':          'Просрочка SLA',
}


class TimelineTabMixin:
    """Builds and drives the Timeline tab."""

    TIMELINE_EVENT_COLUMNS = ["Дата", "Скан", "Событие", "Severity", "Описание"]
    TIMELINE_SERIES_COLUMNS = ["Скан", "Дата", "Risk", "Secrets",
                               "Attack Surface", "High", "Medium"]

    def _build_timeline_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.timeline_project = QComboBox()
        self.timeline_project.setMinimumWidth(220)
        self.timeline_project.currentIndexChanged.connect(self._apply_timeline)
        ctrl.addWidget(self.timeline_project)
        ctrl.addStretch()
        self.timeline_status = QLabel("Событий: 0")
        ctrl.addWidget(self.timeline_status)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_timeline)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # Change feed.
        feed_grp = SectionGroupBox("Лента изменений")
        feed_v = QVBoxLayout()
        self.timeline_events = self._make_timeline_table(self.TIMELINE_EVENT_COLUMNS,
                                                         stretch_col=4)
        feed_v.addWidget(self.timeline_events)
        feed_grp.setLayout(feed_v)
        layout.addWidget(feed_grp, stretch=2)

        # Per-scan metric series (data provider for charts).
        series_grp = SectionGroupBox("Метрики по сканам")
        series_v = QVBoxLayout()
        self.timeline_series = self._make_timeline_table(self.TIMELINE_SERIES_COLUMNS)
        series_v.addWidget(self.timeline_series)
        series_grp.setLayout(series_v)
        layout.addWidget(series_grp, stretch=1)

        self._timeline_widget = w
        return w

    @staticmethod
    def _make_timeline_table(columns, stretch_col=None) -> QTableWidget:
        t = QTableWidget(0, len(columns))
        t.setHorizontalHeaderLabels(columns)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.SingleSelection)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        header = t.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        if stretch_col is not None:
            header.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
        return t

    # ── projects base (same resolution as Scan Diff) ───────────────────────────

    def _timeline_base(self) -> str:
        return (self.settings.get('output_dir', '')
                or str(Path.home() / 'SiteAnalyzer'))

    # ── load: project list ─────────────────────────────────────────────────────

    def _refresh_timeline(self):
        if self._timeline_loading:
            return
        self._timeline_loading = True
        self._set_busy(True)
        base = self._timeline_base()
        self._run_async(lambda b=base: self._query_timeline_projects(b),
                        self._on_timeline_projects)

    @staticmethod
    def _query_timeline_projects(base: str) -> dict:
        try:
            return {'projects': ProjectStore(base).list_projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_timeline_projects(self, result: dict):
        self._timeline_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._timeline_loaded = False
            self.timeline_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._timeline_loaded = True

        current = self.timeline_project.currentData()
        self.timeline_project.blockSignals(True)
        self.timeline_project.clear()
        for meta in result.get('projects', []):
            self.timeline_project.addItem(
                f"{meta.get('slug', '?')} ({meta.get('scan_count', 0)})",
                meta.get('slug'))
        idx = self.timeline_project.findData(current)
        if idx >= 0:
            self.timeline_project.setCurrentIndex(idx)
        self.timeline_project.blockSignals(False)

        self._apply_timeline()

    # ── load: one project's timeline ───────────────────────────────────────────

    def _apply_timeline(self, *args):
        slug = self.timeline_project.currentData()
        if not slug:
            self.timeline_events.setRowCount(0)
            self.timeline_series.setRowCount(0)
            self.timeline_status.setText("Нет проектов")
            return
        if self._timeline_data_loading:
            self._timeline_pending = True
            return
        self._timeline_data_loading = True
        self._set_busy(True)
        base = self._timeline_base()
        self._run_async(lambda b=base, s=slug: self._query_timeline(b, s),
                        self._on_timeline_loaded)

    @staticmethod
    def _query_timeline(base: str, slug: str) -> dict:
        try:
            project = ProjectStore(base).get(slug)
            if project is None:
                return {'error': f'проект не найден: {slug}', 'slug': slug}
            from core.timeline import build_timeline
            tl = build_timeline(project)
            tl['slug'] = slug
            return tl
        except Exception as e:  # noqa: BLE001
            return {'error': str(e), 'slug': slug}

    def _on_timeline_loaded(self, result: dict):
        self._timeline_data_loading = False
        self._set_busy(False)
        if self._timeline_pending:
            self._timeline_pending = False
            self._apply_timeline()
            return
        # Discard a result whose project no longer matches the selection.
        if result.get('slug') != self.timeline_project.currentData():
            return
        if result.get('error'):
            self.timeline_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        events = result.get('events', [])
        self._populate_timeline_events(events)
        self._populate_timeline_series(result.get('series', []))
        self.timeline_status.setText(
            f"Событий: {len(events)} · сканов: {len(result.get('series', []))}")

    def _populate_timeline_events(self, events: list):
        self.timeline_events.setRowCount(0)
        for ev in events:
            r = self.timeline_events.rowCount()
            self.timeline_events.insertRow(r)
            severity = str(ev.get('severity', '')).lower()
            values = [
                (ev.get('at') or '')[:19].replace('T', ' '),
                ev.get('scan_id', ''),
                _EVENT_LABELS.get(ev.get('type'), ev.get('type', '')),
                severity,
                ev.get('title', ''),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col == 3:
                    color = theme.severity_color(severity)
                    if color:
                        item.setForeground(QColor(color))
                self.timeline_events.setItem(r, col, item)

    def _populate_timeline_series(self, series: list):
        self.timeline_series.setRowCount(0)
        # Newest scan first reads better as a quick "where are we now" glance.
        for pt in reversed(series):
            r = self.timeline_series.rowCount()
            self.timeline_series.insertRow(r)
            values = [
                pt.get('scan_id', ''),
                (pt.get('at') or '')[:19].replace('T', ' '),
                pt.get('risk_score'),
                pt.get('secrets'),
                pt.get('attack_surface'),
                pt.get('high'),
                pt.get('medium'),
            ]
            for col, val in enumerate(values):
                self.timeline_series.setItem(
                    r, col, QTableWidgetItem('' if val is None else str(val)))
