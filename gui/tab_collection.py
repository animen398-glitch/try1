"""Final Report & Collection tab — one-click "Run Full Collection".

Runs Recon → API → Capture → Clone → Images into a single project directory
and generates an HTML/JSON report. Mixin folded into MainWindow; uses
_browse, _browse_file, _set_busy, _start_task and _active_collector.
"""

import webbrowser
from pathlib import Path

from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QProgressBar, QSpinBox, QVBoxLayout, QWidget,
)

from core import monitor
from core.collection_runner import CollectionRunner
from core.executive_summary import RISK_COLORS
from core.features import has_katana, has_nuclei, has_playwright
from core.project import ProjectStore
from core.scan_diff import write_diff_report
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from gui.workers import _CollectionWorker, _MonitorWorker


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
        self.collect_screenshot = QCheckBox("Скриншоты ключевых страниц (Playwright)")
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

        # Opt-in local-Ollama AI narrative. A *running service*, not a binary —
        # left enabled with a hint and degraded gracefully at runtime (the phase
        # is skipped if Ollama isn't reachable), so building the tab does no I/O.
        self.collect_llm = QCheckBox("AI-резюме (локальный Ollama)")
        self.collect_llm.setToolTip(
            "Требует запущенного Ollama на localhost:11434 "
            "(иначе фаза пропускается; вердикт риска детерминированный в любом случае)")
        opt_row.addWidget(self.collect_llm)

        # Opt-in subdomain enumeration (passive sources + takeover detection).
        # No binary needed (passive HTTP sources), so a plain checkbox.
        self.collect_subdomains = QCheckBox("Субдомены (passive + takeover)")
        self.collect_subdomains.setToolTip(
            "Перечисление субдоменов (crt.sh/HackerTarget/… + активная проверка "
            "takeover). Доп. сетевые запросы; питает риск-движок и Scan Diff.")
        opt_row.addWidget(self.collect_subdomains)

        # Opt-in TLS certificate capture (one handshake) — feeds Scan Diff.
        self.collect_certificate = QCheckBox("TLS-сертификат")
        self.collect_certificate.setToolTip(
            "Снимает TLS-сертификат хоста (issuer/срок/SAN/отпечаток). "
            "Scan Diff покажет смену сертификата между сканами.")
        opt_row.addWidget(self.collect_certificate)

        # Opt-in OpenAPI/Swagger discovery (#11) — probes for an API spec.
        self.collect_openapi = QCheckBox("OpenAPI / Swagger")
        self.collect_openapi.setToolTip(
            "Ищет спеку API (swagger.json/openapi.json/…) и строит карту "
            "эндпоинтов. Питает отчёт, граф (категория APIs) и Scan Diff.")
        opt_row.addWidget(self.collect_openapi)

        # Opt-in historical URL intelligence (#12) — Wayback archive.
        self.collect_historical = QCheckBox("Историч. URL (Wayback)")
        self.collect_historical.setToolTip(
            "Тянет архивные URL домена из Wayback Machine и классифицирует их "
            "(старые админки/auth/API/конфиги). Питает отчёт, граф и Scan Diff.")
        opt_row.addWidget(self.collect_historical)

        # Opt-in DNS intelligence (#13) — records + email-auth via DoH.
        self.collect_dns = QCheckBox("DNS / Email-auth")
        self.collect_dns.setToolTip(
            "Резолвит DNS-записи (A/MX/TXT/NS/CAA) и email-auth (SPF/DMARC/DKIM) "
            "через DNS-over-HTTPS. Находки (нет SPF/DMARC, слабый DMARC, нет CAA) "
            "идут в риск-движок.")
        opt_row.addWidget(self.collect_dns)
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

        # Scan Diff — compare two scans of a project (reads what the project
        # workspace already stores; all logic in core.scan_diff, thin UI here).
        diff_grp = SectionGroupBox("Scan Diff — что изменилось между сканами")
        dg = QHBoxLayout()
        dg.addWidget(QLabel("Проект:"))
        self.diff_project = QComboBox()
        self.diff_project.setMinimumWidth(160)
        self.diff_project.currentIndexChanged.connect(self._on_diff_project_changed)
        dg.addWidget(self.diff_project)
        dg.addWidget(QLabel("Скан A:"))
        self.diff_scan_a = QComboBox()
        dg.addWidget(self.diff_scan_a)
        dg.addWidget(QLabel("Скан B:"))
        self.diff_scan_b = QComboBox()
        dg.addWidget(self.diff_scan_b)
        btn_diff_refresh = StyledButton("Обновить", style='secondary')
        btn_diff_refresh.clicked.connect(self._refresh_diff_projects)
        dg.addWidget(btn_diff_refresh)
        self.btn_scan_diff = StyledButton("Сравнить")
        self.btn_scan_diff.setEnabled(False)
        self.btn_scan_diff.clicked.connect(self._run_scan_diff)
        dg.addWidget(self.btn_scan_diff)
        dg.addStretch()
        diff_grp.setLayout(dg)
        layout.addWidget(diff_grp)
        self._refresh_diff_projects()

        # Continuous Monitoring (#8) — manage a project's watch schedule and run
        # all due scans now. Thin UI over core.monitor (same store as Scan Diff).
        mon_grp = SectionGroupBox("Continuous Monitoring — расписание + авто-diff")
        mg = QHBoxLayout()
        mg.addWidget(QLabel("Проект:"))
        self.monitor_project = QComboBox()
        self.monitor_project.setMinimumWidth(160)
        self.monitor_project.currentIndexChanged.connect(
            self._on_monitor_project_changed)
        mg.addWidget(self.monitor_project)
        mg.addWidget(QLabel("Интервал:"))
        self.monitor_interval = QComboBox()
        for label, val in (("Ежедневно", "daily"), ("Еженедельно", "weekly"),
                           ("Ежемесячно", "monthly")):
            self.monitor_interval.addItem(label, val)
        mg.addWidget(self.monitor_interval)
        self.btn_monitor_enable = StyledButton("Включить")
        self.btn_monitor_enable.clicked.connect(self._enable_monitor)
        mg.addWidget(self.btn_monitor_enable)
        self.btn_monitor_disable = StyledButton("Выключить", style='secondary')
        self.btn_monitor_disable.clicked.connect(self._disable_monitor)
        mg.addWidget(self.btn_monitor_disable)
        self.btn_monitor_run = StyledButton("Запустить готовые", style='secondary')
        self.btn_monitor_run.clicked.connect(self._run_monitor_due)
        mg.addWidget(self.btn_monitor_run)
        mg.addStretch()
        mon_outer = QVBoxLayout()
        mon_outer.addLayout(mg)
        self.monitor_status = QLabel("Не отслеживается")
        self.monitor_status.setStyleSheet("color:#8b949e;font-size:11px;")
        mon_outer.addWidget(self.monitor_status)
        mon_grp.setLayout(mon_outer)
        layout.addWidget(mon_grp)
        self._refresh_monitor_projects()

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
            llm=self.collect_llm.isChecked(),
            llm_model=self.settings.get('ollama_model') or None,
            subdomains=self.collect_subdomains.isChecked(),
            certificate=self.collect_certificate.isChecked(),
            openapi=self.collect_openapi.isChecked(),
            historical=self.collect_historical.isChecked(),
            dns=self.collect_dns.isChecked(),
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
        # Project workspace context — this scan lives inside a durable project.
        project_root = result.get('project_root')
        if project_root:
            scan_meta = result.get('project_scan') or {}
            self.collect_log.append_info(f"Проект: {project_root}")
            self.collect_log.append_info(
                f"Скан #{scan_meta.get('id', result.get('scan_id', ''))}")
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

        # The finished scan is now indexed — make it comparable right away.
        try:
            self._refresh_diff_projects()
            self._refresh_monitor_projects()
        except Exception:
            pass

    def _open_collection_report(self):
        path = getattr(self, '_collection_report', None)
        if path and Path(path).exists():
            webbrowser.open(Path(path).as_uri())

    # ── Scan Diff ────────────────────────────────────────────────────────────

    def _diff_store(self) -> ProjectStore:
        base = (self.collect_dir.text().strip()
                or self.settings.get('output_dir', '')
                or str(Path.home() / 'SiteAnalyzer'))
        return ProjectStore(base)

    def _refresh_diff_projects(self):
        """Repopulate the project combo from <output>/Projects/ (disk-only,
        bounded: list_projects reads one metadata.json per project)."""
        current = self.diff_project.currentText()
        self.diff_project.blockSignals(True)
        self.diff_project.clear()
        try:
            for meta in self._diff_store().list_projects():
                self.diff_project.addItem(
                    f"{meta.get('slug', '?')} ({meta.get('scan_count', 0)})",
                    meta.get('slug'))
        except Exception:
            pass    # an unreadable store just leaves the combo empty
        idx = self.diff_project.findText(current)
        if idx >= 0:
            self.diff_project.setCurrentIndex(idx)
        self.diff_project.blockSignals(False)
        self._on_diff_project_changed()

    def _on_diff_project_changed(self):
        """Fill the scan combos for the selected project; the compare button
        only lights up once there are two scans to compare."""
        self.diff_scan_a.clear()
        self.diff_scan_b.clear()
        slug = self.diff_project.currentData()
        project = self._diff_store().get(slug) if slug else None
        ids = [s.get('id') for s in (project.scans() if project else [])
               if s.get('id')]
        self.diff_scan_a.addItems(ids)
        self.diff_scan_b.addItems(ids)
        if len(ids) >= 2:
            # Sensible default: previous scan → latest scan.
            self.diff_scan_a.setCurrentIndex(len(ids) - 2)
            self.diff_scan_b.setCurrentIndex(len(ids) - 1)
        self.btn_scan_diff.setEnabled(len(ids) >= 2)
        self.btn_scan_diff.setToolTip(
            '' if len(ids) >= 2 else 'Нужно минимум два скана проекта')

    def _run_scan_diff(self):
        slug = self.diff_project.currentData()
        id_a = self.diff_scan_a.currentText()
        id_b = self.diff_scan_b.currentText()
        if not slug or not id_a or not id_b:
            return
        if id_a == id_b:
            QMessageBox.warning(self, "Scan Diff", "Выберите два разных скана")
            return
        project = self._diff_store().get(slug)
        if project is None:
            QMessageBox.warning(self, "Scan Diff", f"Проект {slug} не найден")
            return
        self.collect_log.append_info(f"Scan Diff: {slug} {id_a} → {id_b}…")
        self._run_async(lambda: write_diff_report(project, id_a, id_b),
                        self._on_scan_diff_done)

    def _on_scan_diff_done(self, result: dict):
        self._set_busy(False)
        self.collect_log.append_success(f"Diff: {result.get('line', '')}")
        path = result.get('html_path')
        if path:
            self.collect_log.append_info(f"Отчёт diff: {path}")
            if Path(path).exists():
                webbrowser.open(Path(path).as_uri())

    # ── Continuous Monitoring (#8) ─────────────────────────────────────────────

    def _refresh_monitor_projects(self):
        """Repopulate the monitoring project combo from <output>/Projects/."""
        current = self.monitor_project.currentData()
        self.monitor_project.blockSignals(True)
        self.monitor_project.clear()
        try:
            for meta in self._diff_store().list_projects():
                self.monitor_project.addItem(meta.get('slug', '?'), meta.get('slug'))
        except Exception:
            pass
        idx = self.monitor_project.findData(current)
        if idx >= 0:
            self.monitor_project.setCurrentIndex(idx)
        self.monitor_project.blockSignals(False)
        self._on_monitor_project_changed()

    def _on_monitor_project_changed(self):
        """Reflect the selected project's schedule in the status label."""
        slug = self.monitor_project.currentData()
        project = self._diff_store().get(slug) if slug else None
        mon = project.get_monitor() if project else None
        if not mon:
            self.monitor_status.setText("Не отслеживается")
            return
        state = "вкл" if mon.get('enabled') else "выкл"
        self.monitor_status.setText(
            f"[{state}] {mon.get('interval', '?')} · "
            f"следующий: {mon.get('next_run', '—')} · "
            f"последний: {mon.get('last_run', '—')}")
        # Keep the interval combo in sync with the stored schedule.
        idx = self.monitor_interval.findData(mon.get('interval'))
        if idx >= 0:
            self.monitor_interval.setCurrentIndex(idx)

    def _monitor_target_url(self):
        """The URL to (un)watch: the selected project's, else the URL field."""
        slug = self.monitor_project.currentData()
        if slug:
            project = self._diff_store().get(slug)
            if project is not None:
                return project.load_metadata().get('url') or slug
        return self.collect_url.text().strip()

    def _enable_monitor(self):
        url = self._monitor_target_url()
        if not url:
            QMessageBox.warning(self, "Monitoring",
                                "Выберите проект или укажите URL")
            return
        interval = self.monitor_interval.currentData()
        out = monitor.enable(self._diff_store(), url, interval)
        self.collect_log.append_success(
            f"Мониторинг включён: {out['slug']} ({interval}); "
            f"первый запуск: {out['schedule']['next_run']}")
        self._refresh_monitor_projects()

    def _disable_monitor(self):
        url = self._monitor_target_url()
        if not url:
            QMessageBox.warning(self, "Monitoring",
                                "Выберите проект или укажите URL")
            return
        out = monitor.disable(self._diff_store(), url)
        if out.get('error'):
            QMessageBox.warning(self, "Monitoring", out['error'])
            return
        self.collect_log.append_warning(f"Мониторинг выключен: {out['slug']}")
        self._refresh_monitor_projects()

    def _run_monitor_due(self):
        """Run all due monitored projects now (Full Collection + auto-diff)."""
        self.collect_log.append_info("Запускаю готовые мониторинг-сканы…")
        self.collect_progress.setRange(0, 0)
        self.collect_progress.setVisible(True)
        self._set_busy(True)
        worker = _MonitorWorker(self._diff_store())
        self._start_task(
            worker,
            on_finished=self._on_monitor_run_done,
            on_error=lambda e: (self._set_busy(False),
                                self.collect_progress.setVisible(False),
                                QMessageBox.critical(self, "Monitoring Error", e)),
            signals=[(worker.log_message, self._on_collection_log)],
        )

    def _on_monitor_run_done(self, result: dict):
        self._set_busy(False)
        self.collect_progress.setVisible(False)
        self.collect_log.append_success(
            f"Мониторинг: запущено проектов — {result.get('ran', 0)}")
        try:
            self._refresh_diff_projects()
            self._refresh_monitor_projects()
        except Exception:
            pass
