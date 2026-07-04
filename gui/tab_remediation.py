"""Remediation tab — the F4 fix-tracking view (EPIC NEXT, GUI tail).

A remediation task is the fix work tracked on a finding (status open/in_progress/
done + optional owner/due/note), event-sourced over ``finding_events`` (no second
table). The core, report card, web ``/remediation`` and ``remediation_cli.py`` were
built in F4; this tab is the human side: pick a project, read the tracked tasks,
edit the selected task's status/owner/due, or seed tasks for the top-priority
findings.

Thin UI mixin folded into MainWindow, mirroring the Findings tab: every DB read/
write runs off the GUI thread via ``_run_async`` (the SQLite connection is opened
and closed inside the worker). Task state lives in ``core.remediation`` /
``core.findings_store`` — this file only renders and dispatches. Workflow state,
not a risk signal.
"""

from qtpy.QtGui import QColor
from qtpy.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.remediation import REMEDIATION_STATUSES, STATUS_LABELS
from gui import theme
from gui.ui_components import (
    FlowLayout, ResultsDisplay, SectionGroupBox, StyledButton, TablePaginator,
)


class RemediationTabMixin:
    """Builds and drives the Remediation Tasks tab."""

    REM_COLUMNS = ["Статус", "Severity", "Находка", "Ответственный", "Срок"]

    # (summary key -> rollup-card caption), from remediation.load_remediation summary.
    REM_ROLLUP = [
        ('total',       'Задач'),
        ('open',        'Открыто'),
        ('in_progress', 'В работе'),
        ('overdue',     'Просрочено'),
    ]

    def _build_remediation_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── control row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Проект:"))
        self.rem_project = QComboBox()
        self.rem_project.setMinimumWidth(220)
        self.rem_project.currentIndexChanged.connect(self._apply_rem_filter)
        ctrl.addWidget(self.rem_project)

        ctrl.addStretch()
        self.rem_status = QLabel("Задач: 0")
        ctrl.addWidget(self.rem_status)
        self.btn_rem_seed = StyledButton("Создать для топ-находок", style='secondary')
        self.btn_rem_seed.setToolTip(
            "Автоматически завести задачи (open) для топ-приоритетных находок "
            "проекта; уже существующие задачи не трогаются.")
        self.btn_rem_seed.clicked.connect(self._seed_remediation)
        ctrl.addWidget(self.btn_rem_seed)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_remediation)
        ctrl.addWidget(btn_refresh)
        layout.addLayout(ctrl)

        # ── rollup cards ────────────────────────────────────────────────────
        rollup_row = FlowLayout()
        self.rem_rollup: dict = {}
        for key, title in self.REM_ROLLUP:
            card, value_label = self._make_stat_card(title)
            self.rem_rollup[key] = value_label
            rollup_row.addWidget(card)
        layout.addLayout(rollup_row)

        # ── tasks table ─────────────────────────────────────────────────────
        self.rem_table = QTableWidget(0, len(self.REM_COLUMNS))
        self.rem_table.setHorizontalHeaderLabels(self.REM_COLUMNS)
        self.rem_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rem_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rem_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.rem_table.verticalHeader().setVisible(False)
        self.rem_table.setAlternatingRowColors(True)
        header = self.rem_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)   # finding title fills
        self.rem_table.itemSelectionChanged.connect(self._on_rem_row_selected)
        layout.addWidget(self.rem_table, stretch=1)
        # Page a large task list so populating the widget never freezes the UI;
        # the full list is kept for selection (mirrors the Findings tab).
        self._rem_paginator = TablePaginator(
            self.rem_table, self._render_rem_row,
            on_page_changed=self._on_rem_page_changed)
        layout.addWidget(self._rem_paginator.widget)

        # ── edit row (acts on the selected task) ────────────────────────────
        edit_grp = SectionGroupBox("Изменить выбранную задачу")
        edit_row = FlowLayout()
        edit_row.addWidget(QLabel("Статус:"))
        self.rem_edit_status = QComboBox()
        for st in REMEDIATION_STATUSES:
            self.rem_edit_status.addItem(STATUS_LABELS.get(st, st), st)
        edit_row.addWidget(self.rem_edit_status)
        edit_row.addWidget(QLabel("Ответственный:"))
        self.rem_edit_owner = QLineEdit()
        self.rem_edit_owner.setPlaceholderText("необязательно")
        self.rem_edit_owner.setMinimumWidth(140)
        edit_row.addWidget(self.rem_edit_owner)
        edit_row.addWidget(QLabel("Срок:"))
        self.rem_edit_due = QLineEdit()
        self.rem_edit_due.setPlaceholderText("YYYY-MM-DD")
        self.rem_edit_due.setMinimumWidth(110)
        edit_row.addWidget(self.rem_edit_due)
        self.btn_rem_apply = StyledButton("Применить")
        self.btn_rem_apply.setEnabled(False)
        self.btn_rem_apply.clicked.connect(self._apply_remediation_edit)
        edit_row.addWidget(self.btn_rem_apply)
        edit_grp.setLayout(edit_row)
        layout.addWidget(edit_grp)

        # ── detail panel ────────────────────────────────────────────────────
        detail_grp = SectionGroupBox("Детали выбранной задачи")
        detail_layout = QVBoxLayout()
        self.rem_detail = ResultsDisplay()
        self.rem_detail.setMaximumHeight(150)
        self.rem_detail.setPlaceholderText(
            "Выберите задачу, чтобы увидеть детали находки и задачи")
        detail_layout.addWidget(self.rem_detail)
        detail_grp.setLayout(detail_layout)
        layout.addWidget(detail_grp)

        self._rem_records: list = []
        self._remediation_widget = w
        return w

    # ── load (stage 1: project list) ──────────────────────────────────────────

    def _refresh_remediation(self):
        if self._rem_loading:
            return
        self._rem_loading = True
        self._set_busy(True)
        self._run_async(self._query_rem_projects, self._on_rem_loaded)

    @staticmethod
    def _query_rem_projects() -> dict:
        try:
            from core.findings_store import FindingsStore
            return {'projects': FindingsStore().projects()}
        except Exception as e:  # noqa: BLE001 — surface as data, never crash UI
            return {'error': str(e)}

    def _on_rem_loaded(self, result: dict):
        self._rem_loading = False
        self._set_busy(False)
        if result.get('error'):
            self._rem_loaded = False
            self.rem_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        self._rem_loaded = True

        current = self.rem_project.currentData()
        self.rem_project.blockSignals(True)
        self.rem_project.clear()
        projects = result.get('projects', [])
        for p in projects:
            self.rem_project.addItem(
                f"{p['project']} ({p['active']}/{p['total']})", p['project'])
        idx = self.rem_project.findData(current)
        self.rem_project.setCurrentIndex(idx if idx >= 0 else 0)
        self.rem_project.blockSignals(False)

        if not projects:
            self.rem_status.setText("Нет проектов с находками")
            self._populate_rem_rollup({})
            self._populate_rem_table([])
            return
        self._apply_rem_filter()

    # ── load (stage 2: per-project tasks) ─────────────────────────────────────

    def _apply_rem_filter(self, *args):
        if self._rem_table_loading:
            self._rem_filter_pending = True
            return
        project = self.rem_project.currentData()
        if not project:
            self._populate_rem_rollup({})
            self._populate_rem_table([])
            self.rem_status.setText("Задач: 0")
            return
        self._rem_table_loading = True
        self._set_busy(True)
        self._run_async(lambda p=project: self._query_rem_table(p),
                        self._on_rem_table_loaded)

    @staticmethod
    def _query_rem_table(project) -> dict:
        try:
            from core.remediation import load_remediation
            return {'project': project, 'data': load_remediation(project)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_rem_table_loaded(self, result: dict):
        self._rem_table_loading = False
        self._set_busy(False)
        if self._rem_filter_pending:
            self._rem_filter_pending = False
            self._apply_rem_filter()
            return
        if result.get('error'):
            self._populate_rem_rollup({})
            self._populate_rem_table([])
            self.rem_status.setText(f"Ошибка загрузки: {result['error']}")
            return
        data = result.get('data') or {}
        summary = data.get('summary') or {}
        tasks = data.get('tasks') or []
        self.rem_status.setText(
            f"Задач: {summary.get('total', 0)}  ·  открыто: "
            f"{summary.get('open', 0)}  ·  просрочено: {summary.get('overdue', 0)}")
        self._populate_rem_rollup(summary)
        self._populate_rem_table(tasks)

    # ── populate ──────────────────────────────────────────────────────────────

    def _populate_rem_rollup(self, summary: dict):
        for key, label in self.rem_rollup.items():
            label.setText(str(summary.get(key, 0)))

    @staticmethod
    def _render_rem_row(table, r: int, rec: dict):
        task = rec.get('task') or {}
        severity = str(rec.get('severity', '')).lower()
        values = [
            rec.get('status_label', task.get('status', '')),
            severity,
            rec.get('title', ''),
            task.get('owner', ''),
            task.get('due', ''),
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 1:
                color = theme.severity_color(severity)
                if color:
                    item.setForeground(QColor(color))
            elif col == 4 and rec.get('overdue'):
                item.setForeground(QColor(theme.severity_color('critical')))
            table.setItem(r, col, item)

    def _populate_rem_table(self, tasks: list):
        self._rem_records = tasks          # full list — selection
        self._rem_paginator.set_rows(tasks)
        self.rem_detail.clear()
        self.btn_rem_apply.setEnabled(False)

    def _on_rem_page_changed(self):
        # A new page carries no selection; clear the stale detail/edit state.
        self.rem_detail.clear()
        self.btn_rem_apply.setEnabled(False)

    # ── selection / detail ────────────────────────────────────────────────────

    def _selected_rem(self) -> dict:
        sel = self.rem_table.selectionModel().selectedRows()
        if not sel:
            return {}
        # The table shows only the current page — map the row to the full-list
        # record via the paginator.
        return self._rem_paginator.record_at(sel[0].row()) or {}

    def _on_rem_row_selected(self):
        rec = self._selected_rem()
        if not rec:
            self.btn_rem_apply.setEnabled(False)
            return
        self.btn_rem_apply.setEnabled(True)
        task = rec.get('task') or {}
        i = self.rem_edit_status.findData(task.get('status'))
        if i >= 0:
            self.rem_edit_status.setCurrentIndex(i)
        self.rem_edit_owner.setText(task.get('owner', ''))
        self.rem_edit_due.setText(task.get('due', ''))
        self._show_rem_detail(rec)

    def _show_rem_detail(self, rec: dict):
        task = rec.get('task') or {}
        lines = [
            f"Находка:    {rec.get('title', '')}",
            f"Severity:   {rec.get('severity', '')}   "
            f"Категория: {rec.get('category', '')}",
            f"Статус задачи: {rec.get('status_label', task.get('status', ''))}"
            + ("   ⚠ просрочено" if rec.get('overdue') else ""),
            f"Ответственный: {task.get('owner', '—')}   Срок: {task.get('due', '—')}",
            f"Обновлено:  {rec.get('updated_at', '')}",
            f"ID находки: {rec.get('finding_id', '')}",
        ]
        if task.get('note'):
            lines.append(f"Заметка:    {task['note']}")
        self.rem_detail.setPlainText("\n".join(lines))

    # ── write: edit a task ─────────────────────────────────────────────────────

    def _apply_remediation_edit(self):
        rec = self._selected_rem()
        fid = rec.get('finding_id')
        if not fid:
            return
        status = self.rem_edit_status.currentData()
        owner = self.rem_edit_owner.text().strip()
        due = self.rem_edit_due.text().strip()
        self.btn_rem_apply.setEnabled(False)
        self._set_busy(True)
        self._run_async(
            lambda f=fid, s=status, o=owner, d=due: self._write_rem_task(f, s, o, d),
            self._on_rem_written,
        )

    @staticmethod
    def _write_rem_task(finding_id, status, owner, due) -> dict:
        try:
            from core.findings_store import FindingsStore
            from core.remediation import set_task
            set_task(FindingsStore(), finding_id, status=status,
                     owner=owner, due=due)
            return {'ok': True}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_rem_written(self, result: dict):
        self._set_busy(False)
        if result.get('error'):
            self.rem_status.setText(f"Ошибка сохранения: {result['error']}")
            return
        self._apply_rem_filter()      # reload so counts + the row refresh

    # ── write: auto-seed tasks for top findings ────────────────────────────────

    def _seed_remediation(self):
        project = self.rem_project.currentData()
        if not project:
            self.rem_status.setText("Выберите проект")
            return
        self.btn_rem_seed.setEnabled(False)
        self._set_busy(True)
        self._run_async(lambda p=project: self._seed_rem_tasks(p),
                        self._on_rem_seeded)

    @staticmethod
    def _seed_rem_tasks(project) -> dict:
        try:
            from core.remediation import seed_from_intelligence
            created = seed_from_intelligence(project, top_n=10)
            return {'created': len(created)}
        except Exception as e:  # noqa: BLE001
            return {'error': str(e)}

    def _on_rem_seeded(self, result: dict):
        self._set_busy(False)
        self.btn_rem_seed.setEnabled(True)
        if result.get('error'):
            self.rem_status.setText(f"Ошибка: {result['error']}")
            return
        self.rem_status.setText(f"Создано задач: {result.get('created', 0)} · обновление…")
        self._apply_rem_filter()
