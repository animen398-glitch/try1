"""Final Report & Collection tab — one-click "Run Full Collection".

Runs Recon → API → Capture → Clone → Images into a single project directory
and generates an HTML/JSON report. Mixin folded into MainWindow; uses
_browse, _browse_file, _set_busy, _start_task and _active_collector.
"""

import webbrowser
from pathlib import Path

from PyQt5.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QProgressBar,
    QSpinBox, QVBoxLayout, QWidget,
)

from core.collection_runner import CollectionRunner
from core.executive_summary import RISK_COLORS
from core.features import has_katana, has_nuclei, has_playwright
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from gui.workers import _CollectionWorker


class FinalReportTabMixin:
    """Builds and drives the Final Report & Collection tab."""

    def _build_collection_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Full Collection")
        g = QVBoxLayout()

        row_url = QHBoxLayout()
        row_url.addWidget(QLabel("URL:"))
        self.collect_url = QLineEdit()
        self.collect_url.setPlaceholderText("https://example.com")
        self.collect_url.returnPressed.connect(self._run_collection)
        row_url.addWidget(self.collect_url)
        g.addLayout(row_url)

        row_out = QHBoxLayout()
        row_out.addWidget(QLabel("Папка:"))
        self.collect_dir = QLineEdit(self.settings.get('output_dir', ''))
        btn_browse = StyledButton("...", style='secondary')
        btn_browse.setMaximumWidth(40)
        btn_browse.clicked.connect(lambda: self._browse(self.collect_dir))
        row_out.addWidget(self.collect_dir)
        row_out.addWidget(btn_browse)
        g.addLayout(row_out)

        row_opts = QHBoxLayout()
        row_opts.addWidget(QLabel("Макс. страниц:"))
        self.collect_pages = QSpinBox()
        self.collect_pages.setRange(1, 200)
        self.collect_pages.setValue(min(int(self.settings.get('max_pages', 20)), 200))
        row_opts.addWidget(self.collect_pages)
        row_opts.addSpacing(12)
        row_opts.addWidget(QLabel("Cookies:"))
        self.collect_cookies = QLineEdit()
        self.collect_cookies.setPlaceholderText("cookies.txt (опц.)")
        btn_ck = StyledButton("...", style='secondary')
        btn_ck.setMaximumWidth(40)
        btn_ck.clicked.connect(lambda: self._browse_file(self.collect_cookies))
        row_opts.addWidget(self.collect_cookies)
        row_opts.addWidget(btn_ck)
        g.addLayout(row_opts)

        # Opt-in headless screenshot (Playwright). Disabled with a hint when
        # Playwright is absent — the feature-gating pattern used elsewhere.
        opt_row = QHBoxLayout()
        self.collect_screenshot = QCheckBox("Скриншот страницы (Playwright)")
        if not has_playwright():
            self.collect_screenshot.setEnabled(False)
            self.collect_screenshot.setToolTip(
                "Требуется Playwright: pip install playwright "
                "&& python -m playwright install chromium")
        opt_row.addWidget(self.collect_screenshot)

        # Opt-in external nuclei scan — gated on the binary being on PATH.
        self.collect_nuclei = QCheckBox("Nuclei (внешний сканер)")
        if not has_nuclei():
            self.collect_nuclei.setEnabled(False)
            self.collect_nuclei.setToolTip(
                "Требуется бинарь nuclei на PATH "
                "(https://github.com/projectdiscovery/nuclei)")
        opt_row.addWidget(self.collect_nuclei)

        # Opt-in external katana crawl — gated on the binary being on PATH.
        self.collect_katana = QCheckBox("Katana (внешний краулер)")
        if not has_katana():
            self.collect_katana.setEnabled(False)
            self.collect_katana.setToolTip(
                "Требуется бинарь katana на PATH "
                "(https://github.com/projectdiscovery/katana)")
        opt_row.addWidget(self.collect_katana)
        opt_row.addStretch()
        g.addLayout(opt_row)

        btn_row = QHBoxLayout()
        self.btn_collect_run = StyledButton("Run Full Collection")
        self.btn_collect_run.clicked.connect(self._run_collection)
        self.btn_collect_stop = StyledButton("Остановить", style='secondary')
        self.btn_collect_stop.setEnabled(False)
        self.btn_collect_stop.clicked.connect(self._stop_collection)
        self.btn_collect_report = StyledButton("Открыть отчёт", style='secondary')
        self.btn_collect_report.setEnabled(False)
        self.btn_collect_report.clicked.connect(self._open_collection_report)
        btn_row.addWidget(self.btn_collect_run)
        btn_row.addWidget(self.btn_collect_stop)
        btn_row.addStretch()
        btn_row.addWidget(self.btn_collect_report)
        g.addLayout(btn_row)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Прогресс сбора")
        res_layout = QVBoxLayout()
        self.collect_progress = QProgressBar()
        self.collect_progress.setMaximumHeight(14)
        self.collect_progress.setVisible(False)
        res_layout.addWidget(self.collect_progress)
        self.collect_log = ResultsDisplay()
        res_layout.addWidget(self.collect_log)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp, stretch=1)
        return w

    def _run_collection(self):
        url = self.collect_url.text().strip()
        base = self.collect_dir.text().strip()
        if not url or not base:
            QMessageBox.warning(self, "Ошибка", "Укажите URL и папку")
            return

        self.collect_log.clear()
        self.collect_log.append_info(f"Запускаю Full Collection: {url}")
        self.collect_progress.setRange(0, 0)
        self.collect_progress.setVisible(True)
        self.btn_collect_run.setEnabled(False)
        self.btn_collect_stop.setEnabled(True)
        self.btn_collect_report.setEnabled(False)
        self._set_busy(True)

        runner = CollectionRunner(
            profile=self.settings.get('user_agent_profile', 'chrome_windows'),
            max_pages=self.collect_pages.value(),
            cookies=self.collect_cookies.text().strip() or None,
            capture_delay=self.settings.get('request_delay', 500) / 1000.0,
            screenshots=self.collect_screenshot.isChecked(),
            nuclei=self.collect_nuclei.isChecked(),
            katana=self.collect_katana.isChecked(),
        )
        self._active_collector = runner

        worker = _CollectionWorker(runner, url, base)
        self._start_task(
            worker,
            on_finished=self._on_collection_done,
            on_error=lambda e: (self._reset_collection_buttons(),
                                self._set_busy(False),
                                self.collect_progress.setVisible(False),
                                QMessageBox.critical(self, "Collection Error", e)),
            signals=[(worker.log_message, self._on_collection_log)],
        )

    def _on_collection_log(self, msg: str):
        m = msg.strip()
        if m.startswith('[') and ']' in m.split(' ')[0]:
            self.collect_log.append(
                f'<span style="color:#4fc3f7;font-weight:bold;">{msg}</span>'
            )
        elif 'failed' in m.lower() or 'отменён' in m.lower():
            self.collect_log.append_warning(msg)
        else:
            self.collect_log.append_info(msg)

    def _stop_collection(self):
        if getattr(self, '_active_collector', None):
            self._active_collector.cancel()
            self.collect_log.append_warning("Останавливаю сбор после текущей фазы…")
        self.btn_collect_stop.setEnabled(False)

    def _reset_collection_buttons(self):
        self._active_collector = None
        self.btn_collect_run.setEnabled(True)
        self.btn_collect_stop.setEnabled(False)

    def _on_collection_done(self, result: dict):
        self._set_busy(False)
        self._reset_collection_buttons()
        self.collect_progress.setVisible(False)

        status = result.get('status', '')
        phases = result.get('phases', {})
        ok = sum(1 for p in phases.values() if p.get('status') == 'Success')
        self.collect_log.append('')
        if status == 'Cancelled':
            self.collect_log.append_warning(f"Сбор отменён — успешных фаз: {ok}/{len(phases)}")
        else:
            self.collect_log.append_success(
                f"Сбор завершён — успешных фаз: {ok}/{len(phases)}"
            )
        self.collect_log.append_info(f"Директория: {result.get('project_dir', '')}")

        # Executive summary — risk verdict + top recommendation up front.
        summary = result.get('executive_summary') or {}
        if summary:
            level = summary.get('risk_level', '—')
            color = RISK_COLORS.get(level, '#888')
            self.collect_log.append(
                f'<span style="color:{color};font-weight:bold;">[РИСК: {level}]</span>'
                f' risk score {summary.get("risk_score", 0)}'
            )
            recs = summary.get('recommendations') or []
            if recs:
                self.collect_log.append_info(f"Рекомендация: {recs[0]}")

        self._collection_report = result.get('report_html')
        if self._collection_report:
            self.collect_log.append_success(f"Отчёт: {self._collection_report}")
            self.btn_collect_report.setEnabled(True)

    def _open_collection_report(self):
        path = getattr(self, '_collection_report', None)
        if path and Path(path).exists():
            webbrowser.open(Path(path).as_uri())
