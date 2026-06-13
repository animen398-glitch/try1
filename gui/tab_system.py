"""System tab: task queue, data export and live log viewer.

Implemented as a mixin folded into MainWindow. Methods reference shared
helpers (self.task_manager, self.status_bar, …) that live on the main window.
"""

from PyQt5.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QVBoxLayout, QWidget,
)

from core import features
from core.analyzer_plugins import discover_analyzers
from core.config import PLUGINS_DIR
from gui.constants import REGISTRY_DB
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from utils.endpoint_index import EndpointIndex
from utils.exporter import DataExporter
from utils.system_logger import get_last_logs


class SystemTabMixin:
    """Builds and drives the System tab."""

    @staticmethod
    def _discover_analyzer_names() -> list:
        """Analyzer plugins found in plugins/analyzers/ as ``name vX`` (never raises)."""
        try:
            plugins = discover_analyzers(PLUGINS_DIR / 'analyzers')
            return [f"{p.name}  v{getattr(p, 'version', '1.0')}" for p in plugins]
        except Exception:
            return []

    def _build_system_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        # ── Task queue ───────────────────────────────────────────────────
        q_grp = SectionGroupBox("Очередь задач")
        q = QVBoxLayout()
        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.task_url = QLineEdit()
        self.task_url.setPlaceholderText("https://example.com")
        self.task_url.returnPressed.connect(self._add_task_to_queue)
        btn_add = StyledButton("Add to Queue")
        btn_add.clicked.connect(self._add_task_to_queue)
        row.addWidget(self.task_url)
        row.addWidget(btn_add)
        q.addLayout(row)
        self.task_queue_label = QLabel("В очереди: 0")
        self.task_queue_label.setStyleSheet("color:#888; font-size:11px;")
        q.addWidget(self.task_queue_label)
        q_grp.setLayout(q)
        layout.addWidget(q_grp)

        # ── Export ───────────────────────────────────────────────────────
        e_grp = SectionGroupBox("Экспорт данных (DataRegistry)")
        e = QHBoxLayout()
        btn_csv = StyledButton("Export CSV", style='secondary')
        btn_csv.clicked.connect(lambda: self._export_data('csv'))
        btn_json = StyledButton("Export JSON", style='secondary')
        btn_json.clicked.connect(lambda: self._export_data('json'))
        btn_endpoints = StyledButton("Export Endpoints", style='secondary')
        btn_endpoints.clicked.connect(self._export_endpoints)
        e.addWidget(btn_csv)
        e.addWidget(btn_json)
        e.addWidget(btn_endpoints)
        e.addStretch()
        e_grp.setLayout(e)
        layout.addWidget(e_grp)

        # ── Optional capabilities ────────────────────────────────────────
        cap_grp = SectionGroupBox("Возможности (опциональные зависимости)")
        cap = QVBoxLayout()
        for name, info in features.summary().items():
            ok = info['available']
            row = QLabel(
                f"{'✓' if ok else '✗'}  {name} — {info['enables']}"
            )
            row.setStyleSheet(
                f"color:{'#81c784' if ok else '#e57373'}; font-size:11px;"
            )
            cap.addWidget(row)
        cap_grp.setLayout(cap)
        layout.addWidget(cap_grp)

        # ── Analyzer plugins (discovered in plugins/analyzers/) ───────────
        ana_grp = SectionGroupBox("Analyzer-плагины (plugins/analyzers/)")
        ana = QVBoxLayout()
        names = self._discover_analyzer_names()
        if names:
            for name in names:
                row = QLabel(f"• {name}")
                row.setStyleSheet("color:#81c784; font-size:11px;")
                ana.addWidget(row)
        else:
            hint = QLabel("Плагины не найдены. См. plugins/analyzers/"
                          "example_analyzer.py.example")
            hint.setStyleSheet("color:#888; font-size:11px;")
            ana.addWidget(hint)
        ana_grp.setLayout(ana)
        layout.addWidget(ana_grp)

        # ── Logs ─────────────────────────────────────────────────────────
        l_grp = SectionGroupBox("Системные логи (последние 50)")
        l = QVBoxLayout()
        self.system_logs = ResultsDisplay()
        l.addWidget(self.system_logs)
        btn_refresh = StyledButton("Обновить", style='secondary')
        btn_refresh.clicked.connect(self._refresh_logs)
        l.addWidget(btn_refresh)
        l_grp.setLayout(l)
        layout.addWidget(l_grp, stretch=1)

        self._refresh_logs()
        return w

    def _add_task_to_queue(self):
        url = self.task_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return
        try:
            self.task_manager.add_task(url)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось добавить задачу: {e}")
            return
        self.task_url.clear()
        self.task_queue_label.setText(f"В очереди: {self.task_manager.queue.qsize()}")
        self.status_bar.showMessage(f"Задача добавлена: {url}")
        self._refresh_logs()

    def _refresh_logs(self):
        try:
            lines = get_last_logs(50)
        except Exception as e:
            lines = [f"Ошибка чтения логов: {e}\n"]
        self.system_logs.setPlainText(''.join(lines))
        scrollbar = self.system_logs.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _export_data(self, fmt: str):
        suffix = fmt.lower()
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить экспорт", f"registry_export.{suffix}",
            f"{fmt.upper()} (*.{suffix})",
        )
        if not path:
            return
        try:
            ok = DataExporter.export(path, format=suffix)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))
            return
        if ok:
            QMessageBox.information(self, "Экспорт", f"Данные сохранены:\n{path}")
        else:
            QMessageBox.warning(self, "Экспорт", "Нет данных для экспорта")

    def _export_endpoints(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт API-эндпоинтов", "api_endpoints.json",
            "JSON (*.json);;CSV (*.csv)",
        )
        if not path:
            return
        suffix = 'csv' if path.lower().endswith('.csv') else 'json'
        try:
            ok = DataExporter.export(path, format=suffix, data_type='api_endpoint')
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))
            return
        if not ok:
            QMessageBox.warning(self, "Экспорт", "Нет эндпоинтов для экспорта")
            return
        # Дедуплицированная сводка для информативного сообщения.
        try:
            s = EndpointIndex(db_path=str(REGISTRY_DB)).get_summary()
            extra = (f"\n\nЗаписей: {s['total_records']} | "
                     f"уникальных эндпоинтов: {s['unique_endpoints']}")
        except Exception:
            extra = ""
        QMessageBox.information(self, "Экспорт", f"Эндпоинты сохранены:\n{path}{extra}")
