"""Recon & Intel tab — GeoIP/CMS recon, optional dynamic sniffing and
paywall bypass, vuln scan, plus the full-API-response dump.

Mixin folded into MainWindow; uses shared helpers (_set_busy, _run_async,
_domain_slug, _save_target) and _last_recon_combined.
"""

import os
import webbrowser
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QVBoxLayout, QWidget,
)

from core import vuln_report
from core.api_dumper import ApiDumper
from core.dynamic_analyzer import DynamicAnalyzer
from core.features import has_playwright
from core.paywall_bypass import PaywallBypass
from core.recon_engine import ReconEngine, enrich_cms_with_dynamic
from core.vuln_scanner import VulnScanner
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton


class ReconTabMixin:
    """Builds and drives the Recon & Intel tab and the API dump action."""

    def _build_recon_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Цель и параметры разведки")
        g = QVBoxLayout()

        row_url = QHBoxLayout()
        row_url.addWidget(QLabel("URL:"))
        self.recon_url = QLineEdit()
        self.recon_url.setPlaceholderText("https://example.com")
        self.recon_url.returnPressed.connect(self._run_recon)
        row_url.addWidget(self.recon_url)
        g.addLayout(row_url)

        row_opts = QHBoxLayout()
        self.chk_dynamic = QCheckBox("Dynamic API Sniffing")
        self.chk_dynamic.setToolTip(
            "Запускает headless Chromium (Playwright) для перехвата XHR/Fetch запросов.\n"
            "Требует: pip install playwright && python -m playwright install chromium"
        )
        if not has_playwright():
            # Same upfront-degradation pattern as the Scrapy plugin: disable the
            # control and say how to enable it, instead of failing only on Run.
            self.chk_dynamic.setText("Dynamic API Sniffing (Playwright не установлен)")
            self.chk_dynamic.setEnabled(False)
            self.chk_dynamic.setToolTip(
                "Недоступно: не установлен Playwright.\n"
                "Установите: pip install playwright && python -m playwright install chromium"
            )
        self.chk_paywall = QCheckBox("Paywall Bypass")
        self.chk_paywall.setToolTip(
            "Последовательно применяет Googlebot-спуфинг, вырезание JS-блоков\n"
            "и запрос архивного снимка Wayback Machine."
        )
        btn_run = StyledButton("Запустить Recon")
        btn_run.clicked.connect(self._run_recon)
        self.btn_dump_api = StyledButton("Dump Full API Responses", style='secondary')
        self.btn_dump_api.setToolTip(
            "Сохраняет все перехваченные API endpoints, JSON-структуры и секреты\n"
            "в папку на диске. Требует выполнения Dynamic API Sniffing."
        )
        self.btn_dump_api.setEnabled(False)
        self.btn_dump_api.clicked.connect(self._run_dump_api)
        self.btn_export_vulns = StyledButton("Export Vuln Report", style='secondary')
        self.btn_export_vulns.setToolTip(
            "Сохраняет отчёт об уязвимостях (HTML + JSON) на диск.\n"
            "Доступно после завершения разведки."
        )
        self.btn_export_vulns.setEnabled(False)
        self.btn_export_vulns.clicked.connect(self._export_vuln_report)
        row_opts.addWidget(self.chk_dynamic)
        row_opts.addSpacing(12)
        row_opts.addWidget(self.chk_paywall)
        row_opts.addStretch()
        row_opts.addWidget(self.btn_export_vulns)
        row_opts.addSpacing(8)
        row_opts.addWidget(self.btn_dump_api)
        row_opts.addSpacing(8)
        row_opts.addWidget(btn_run)
        g.addLayout(row_opts)

        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Результаты разведки")
        res_layout = QVBoxLayout()
        self.recon_results = ResultsDisplay()
        res_layout.addWidget(self.recon_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_recon(self):
        url = self.recon_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Введите URL")
            return

        self.recon_results.clear()
        self.recon_results.append_info(f"Запускаю разведку: {url}")
        self._set_busy(True)

        do_dynamic = self.chk_dynamic.isChecked()
        do_paywall = self.chk_paywall.isChecked()
        output_dir = self.settings.get('output_dir', str(Path.home() / 'SiteAnalyzer'))
        profile    = self.settings.get('user_agent_profile', 'chrome_windows')

        log = self.recon_results   # safe reference for closure

        def _work():
            combined: dict = {'url': url, 'recon': {}, 'dynamic': {}, 'paywall': {}}

            # ── Phase 1: GeoIP + CMS + favicons (always) ──────────────────
            engine = ReconEngine()
            engine.configure(profile=profile)
            combined['recon'] = engine.run_recon(url)

            # ── Phase 2: Paywall bypass (optional) ────────────────────────
            if do_paywall:
                log.append_info("Запускаю Paywall Bypass...")
                bypass = PaywallBypass()
                bypass.configure(profile=profile)
                pw = bypass.extract(url)
                if pw.get('html'):
                    domain = self._domain_slug(url)
                    out_file = (
                        Path(output_dir)
                        / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}_bypass.html"
                    )
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_text(pw['html'], encoding='utf-8')
                    pw['saved_to'] = str(out_file)
                combined['paywall'] = {k: v for k, v in pw.items() if k != 'html'}

            # ── Phase 3: Dynamic traffic interception (optional) ──────────
            if do_dynamic:
                analyzer = DynamicAnalyzer()
                analyzer.configure(timeout_ms=25000, wait_ms=3000)
                analyzer.set_progress_callback(lambda msg: log.append_info(msg))
                combined['dynamic'] = analyzer.analyze_dynamic_traffic(url)
                if combined['dynamic'].get('status') == 'Success':
                    enrich_cms_with_dynamic(combined['recon'], combined['dynamic'])

            # ── Phase 4: Vulnerability scan (always) ──────────────────────
            combined['vulns'] = VulnScanner().scan(
                combined.get('recon', {}), combined.get('dynamic', {})
            )

            return combined

        self._run_async(_work, self._on_recon_done)

    def _on_recon_done(self, result: dict):
        self._set_busy(False)
        D = "─" * 52

        # ── GeoIP + infrastructure ────────────────────────────────────────
        recon = result.get('recon', {})
        if recon.get('status') == 'Success':
            self.recon_results.append_info(D)
            geo = recon.get('geo', {})

            if recon.get('ip'):
                self.recon_results.append(f"  IP Address   : {recon['ip']}")
            if geo.get('country'):
                region = geo.get('regionName', '')
                city   = geo.get('city', '?')
                loc    = f"{city}, {region}, {geo['country']}" if region else f"{city}, {geo['country']}"
                self.recon_results.append(f"  Location     : {loc}")
            if geo.get('isp'):
                self.recon_results.append(f"  ISP          : {geo['isp']}")
            if geo.get('as'):
                self.recon_results.append(f"  ASN          : {geo['as']}")
            if geo.get('org') and geo.get('org') != geo.get('isp'):
                self.recon_results.append(f"  Organisation : {geo['org']}")

            # Server headers
            for k, v in recon.get('server_headers', {}).items():
                self.recon_results.append(f"  {k:<13}: {v}")

            # CMS / tech stack — extended
            self.recon_results.append_info(D)
            cms         = recon.get('cms', [])
            cms_details = recon.get('cms_details', {})
            if cms:
                self.recon_results.append_success(
                    f"  Stack detected ({len(cms)}):"
                )
                for fw in cms:
                    self.recon_results.append_success(f"    [+] {fw}")
                    for indicator in cms_details.get(fw, [])[:3]:
                        self.recon_results.append_info(
                            f"         indicator : {indicator}"
                        )
            else:
                self.recon_results.append("  CMS / Stack  : не определён")

            # Favicons
            favicons = recon.get('favicons', [])
            if favicons:
                self.recon_results.append_info(f"  Favicons ({len(favicons)}):")
                for fav in favicons[:6]:
                    self.recon_results.append(f"    • [{fav['type']}]  {fav['url']}")

            # PWA manifest
            manifest = recon.get('pwa_manifest', {})
            if manifest:
                name = manifest.get('data', {}).get('name', 'PWA')
                self.recon_results.append_success(
                    f"  PWA Manifest : {name}  ({manifest.get('url', '')})"
                )
        else:
            self.recon_results.append_error(
                f"  Recon: {recon.get('error', 'неизвестная ошибка')}"
            )

        # ── Paywall bypass ────────────────────────────────────────────────
        paywall = result.get('paywall', {})
        if paywall:
            self.recon_results.append_info(D)
            paywalled = paywall.get('paywalled', False)
            strategy  = paywall.get('strategy_used') or '—'
            pw_status = paywall.get('status', 'Failed')
            self.recon_results.append(
                f"  Paywall      : {'Обнаружен' if paywalled else 'Не обнаружен'}"
            )
            if pw_status == 'Success':
                self.recon_results.append_success(f"  Bypass       : {strategy}")
                if paywall.get('saved_to'):
                    self.recon_results.append_info(f"  Сохранён в   : {paywall['saved_to']}")
            else:
                self.recon_results.append_warning("  Bypass       : все стратегии не сработали")

        # ── Dynamic analysis ──────────────────────────────────────────────
        dynamic = result.get('dynamic', {})
        if dynamic.get('status') == 'Success':
            self.recon_results.append_info(D)
            self.recon_results.append_success(
                f"  API-вызовов  : {dynamic['total_api_calls']} "
                f"({dynamic['unique_hosts']} уникальных хостов)"
            )

            endpoints = dynamic.get('endpoints', [])
            if endpoints:
                self.recon_results.append_info(f"  XHR / Fetch endpoints ({len(endpoints)}):")
                for ep in endpoints[:25]:
                    path   = ep.get('path', '/')[:48]
                    host   = ep.get('host', '')
                    method = ep.get('method', 'GET')
                    code   = ep.get('status', 0)
                    self.recon_results.append(
                        f"    {method:<5} {code:>3}  {path:<50}  {host}"
                    )
                if len(endpoints) > 25:
                    self.recon_results.append_info(
                        f"    … и ещё {len(endpoints) - 25} endpoints"
                    )

            auth_hdrs = dynamic.get('auth_headers', [])
            if auth_hdrs:
                self.recon_results.append_warning(
                    f"  Auth-заголовки ({len(auth_hdrs)}):"
                )
                for ah in auth_hdrs[:10]:
                    self.recon_results.append_warning(
                        f"    {ah['header']}: {ah['preview']}"
                        f"  [{ah['url'][-55:]}]"
                    )

            structs = dynamic.get('json_structures', [])

            # ── Secrets / tokens inside JSON payloads ─────────────────────
            payload_secrets = dynamic.get('secrets_found', [])
            if payload_secrets:
                self.recon_results.append_warning(D)
                self.recon_results.append_warning(
                    f"  [!!] SECRETS IN JSON PAYLOADS ({len(payload_secrets)}):"
                )
                for sec in payload_secrets[:20]:
                    self.recon_results.append_warning(
                        f"    [{sec['type']:<14}]  key='{sec['key']}'"
                        f"  =>  '{sec['preview']}'"
                    )
                    self.recon_results.append_info(
                        f"                    {sec['source_url'][-60:]}"
                    )

            # ── Runtime globals detected by Playwright JS probe ───────────
            runtime_globals = dynamic.get('runtime_globals', {})
            if runtime_globals:
                names = list(runtime_globals.keys())
                self.recon_results.append_success(
                    f"  Runtime globals ({len(names)}):"
                )
                for fw in names:
                    self.recon_results.append_success(f"    [window] {fw}")

            # ── JSON response structures with sample values ────────────────
            if structs:
                self.recon_results.append_info(
                    f"  JSON-структуры ответов ({len(structs)}):"
                )
                for js in structs[:10]:
                    keys   = js.get('top_keys') or js.get('item_keys', [])
                    suffix = f"  [array x {js['length']}]" if js.get('type') == 'array' else ''
                    url_s  = js.get('url', '')[-58:]
                    self.recon_results.append_info(f"    {url_s}{suffix}")
                    self.recon_results.append(f"      keys : {keys[:10]}")
                    for k, v in list(js.get('sample', {}).items())[:4]:
                        self.recon_results.append(
                            f"        {k:<20} : {str(v)[:60]}"
                        )

        elif dynamic.get('status') == 'Error':
            self.recon_results.append_info(D)
            self.recon_results.append_error(
                f"  Dynamic: {dynamic.get('error', '')}"
            )

        # ── Discovered Vulnerabilities ─────────────────────────────────────
        vulns = result.get('vulns', [])
        if vulns:
            self.recon_results.append_info(D)
            highs   = [v for v in vulns if v['severity'] == 'High']
            mediums = [v for v in vulns if v['severity'] == 'Medium']
            infos   = [v for v in vulns if v['severity'] == 'Info']
            self.recon_results.append(
                f"  Discovered Vulns: {len(highs)} High  |  "
                f"{len(mediums)} Medium  |  {len(infos)} Info"
            )
            for v in highs:
                self.recon_results.append_high(f"  {v['title']}")
                if v.get('detail'):
                    self.recon_results.append_info(f"    {v['detail'][:120]}")
            for v in mediums:
                self.recon_results.append_medium(f"  {v['title']}")
                if v.get('detail'):
                    self.recon_results.append_info(f"    {v['detail'][:120]}")
            for v in infos:
                self.recon_results.append_success(f"  {v['title']}")
                if v.get('detail'):
                    self.recon_results.append_info(f"    {v['detail'][:100]}")

        # Store result + activate dump button if dynamic data is present
        self._last_recon_combined = result
        self.btn_dump_api.setEnabled(
            result.get('dynamic', {}).get('status') == 'Success'
        )
        self.btn_export_vulns.setEnabled(bool(result.get('vulns')))

        self.recon_results.append_info(D)
        self.recon_results.append_success("Разведка завершена")
        self._save_target(self.recon_url.text().strip())

    def _export_vuln_report(self):
        findings = self._last_recon_combined.get('vulns', [])
        if not findings:
            QMessageBox.information(self, "Vuln Report", "Нет данных об уязвимостях.")
            return
        url = self._last_recon_combined.get('url', '')
        domain = self._domain_slug(url)
        default = f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}_vulns.html"
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт vuln-отчёта", default, "HTML (*.html)"
        )
        if not path:
            return
        try:
            paths = vuln_report.export(path, url, findings)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", str(e))
            return
        formats = ', '.join(sorted(paths)).upper()
        self.recon_results.append_success(
            f"Vuln-отчёт сохранён ({formats}): {paths['html']}"
        )
        if QMessageBox.question(
            self, "Vuln Report",
            f"Отчёт сохранён:\n{paths['html']}\n\nОткрыть в браузере?",
        ) == QMessageBox.Yes:
            webbrowser.open(Path(paths['html']).as_uri())

    # --------------------------------------------------- API dump handlers

    def _run_dump_api(self):
        dynamic = self._last_recon_combined.get('dynamic', {})
        if dynamic.get('status') != 'Success':
            QMessageBox.information(
                self, "API Dump",
                "Сначала запустите сканирование с включённым 'Dynamic API Sniffing'.",
            )
            return
        output_dir = self.settings.get('output_dir', str(Path.home() / 'SiteAnalyzer'))
        url = self._last_recon_combined.get('url', '')
        dumper = ApiDumper()
        dumper.configure(output_dir)
        self.btn_dump_api.setEnabled(False)
        self.recon_results.append_info("Сохраняю полные API ответы на диск...")
        self._set_busy(True)
        _dyn = dynamic
        _url = url

        def _work():
            return dumper.dump(_dyn, _url)

        self._run_async(_work, self._on_dump_done)

    def _on_dump_done(self, result: dict):
        self._set_busy(False)
        self.btn_dump_api.setEnabled(True)
        if result.get('status') == 'Success':
            out = result['output_dir']
            self.recon_results.append_success(
                f"  Dump завершён — {result['files_written']} файлов, "
                f"{result['endpoint_count']} endpoints"
            )
            self.recon_results.append_info(f"  Папка: {out}")
            try:
                os.startfile(out)
            except Exception:
                pass
        else:
            self.recon_results.append_error(
                f"  Dump ошибка: {result.get('error', '')}"
            )
