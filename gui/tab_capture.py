"""Site Capture tab — crawls a site, saves pages, scans them for leaks.

Mixin folded into MainWindow; uses shared helpers (_domain_slug, _set_busy,
_start_task, _folder_size, _fmt_size, _make_archive) and _active_capturer.
"""

import re
from datetime import datetime
from pathlib import Path

from qtpy.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QVBoxLayout, QWidget,
)

from core.content_capture import SiteContentCapture
from core.secret_scanner import SecretScanner
from core.site_map import GROUP_ORDER
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from gui.workers import _CaptureWorker


class CaptureTabMixin:
    """Builds and drives the Site Capture tab."""

    def _build_capture_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Настройки захвата")
        g = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("URL:"))
        self.capture_url = QLineEdit()
        self.capture_url.setPlaceholderText("https://example.com")
        row1.addWidget(self.capture_url)
        g.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Папка:"))
        self.capture_dir = QLineEdit(self.settings.get('output_dir', ''))
        btn_browse = StyledButton("...", style='secondary')
        btn_browse.setMaximumWidth(40)
        btn_browse.clicked.connect(lambda: self._browse(self.capture_dir))
        row2.addWidget(self.capture_dir)
        row2.addWidget(btn_browse)
        g.addLayout(row2)

        btn_row = QHBoxLayout()
        self.btn_capture_start = StyledButton("Начать захват")
        self.btn_capture_start.clicked.connect(self._run_capture)
        self.btn_capture_stop = StyledButton("Остановить", style='secondary')
        self.btn_capture_stop.setEnabled(False)
        self.btn_capture_stop.clicked.connect(self._stop_capture)
        btn_row.addWidget(self.btn_capture_start)
        btn_row.addWidget(self.btn_capture_stop)
        g.addLayout(btn_row)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Лог захвата")
        res_layout = QVBoxLayout()
        self.capture_log = ResultsDisplay()
        res_layout.addWidget(self.capture_log)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_capture(self):
        url = self.capture_url.text().strip()
        base_out = self.capture_dir.text().strip()
        if not url or not base_out:
            QMessageBox.warning(self, "Ошибка", "Укажите URL и папку")
            return

        domain = self._domain_slug(url)
        out_path = Path(base_out) / f"{domain}_{datetime.now().strftime('%Y%m%d')}"

        self.capture_log.clear()
        self.capture_log.append_info(f"Начинаю захват: {url}")
        self.capture_log.append_info(f"Директория: {out_path}")
        self._set_busy(True)

        capturer = SiteContentCapture()
        capturer.configure(
            url, str(out_path),
            self.settings.get('max_pages', 50),
            profile=self.settings.get('user_agent_profile', 'chrome_windows'),
            delay=self.settings.get('request_delay', 500) / 1000.0,
        )
        self._active_capturer = capturer
        self.btn_capture_start.setEnabled(False)
        self.btn_capture_stop.setEnabled(True)

        worker = _CaptureWorker(capturer)
        self._start_task(
            worker,
            on_finished=lambda r, _p=out_path, _d=domain: self._on_capture_done(r, _p, _d),
            on_error=lambda e: (self._reset_capture_buttons(),
                                self._set_busy(False),
                                QMessageBox.critical(self, "Ошибка захвата", e)),
            signals=[(worker.log_message, self.capture_log.append_info)],
        )

    def _stop_capture(self):
        if getattr(self, '_active_capturer', None):
            self._active_capturer.cancel()
            self.capture_log.append_warning("Останавливаю захват…")
        self.btn_capture_stop.setEnabled(False)

    def _reset_capture_buttons(self):
        self._active_capturer = None
        self.btn_capture_start.setEnabled(True)
        self.btn_capture_stop.setEnabled(False)

    def _on_capture_done(self, result: dict, out_path: Path, domain: str):
        self._reset_capture_buttons()
        if result.get('cancelled'):
            self.capture_log.append_warning("Захват отменён пользователем")
        self._set_busy(False)
        self.capture_log.append_success(
            f"Захвачено страниц: {result.get('pages_captured', 0)}"
        )
        self.capture_log.append_info(f"Директория: {out_path}")

        if out_path.exists():
            size = self._folder_size(out_path)
            self.capture_log.append_info(f"Объём данных: {self._fmt_size(size)}")

        if result.get('errors'):
            self.capture_log.append_warning(
                f"Недоступных URL при обходе: {len(result['errors'])}"
            )

        # Site map: per-status-group breakdown of every visited URL. The full
        # tree is written to site_map.json and rendered in the HTML report.
        summary = result.get('status_summary') or {}
        parts = [f"{g}: {summary[g]}" for g in GROUP_ORDER if summary.get(g)]
        if parts:
            self.capture_log.append_info(
                "Карта сайта (статусы) — " + ", ".join(parts)
                + f" · всего {summary.get('total', 0)} URL (site_map.json)"
            )

        archive = self._make_archive(out_path, domain, 'capture')
        if archive:
            self.capture_log.append_success(f"Архив создан: {Path(archive).name}")
        elif self.settings.get('auto_compress', False):
            self.capture_log.append_warning("Архивация пропущена — папка пуста или не найдена")

        files = [str(p) for p in out_path.glob('**/*') if p.is_file()] if out_path.exists() else []
        if files:
            stats = self._analyse_capture_files(files)
            self.capture_log.append('')
            self.capture_log.append(
                f'<span style="color:#ff5252;font-weight:bold;">[🚨]</span>'
                f' Найдено потенциальных утечек ключей: {stats["key_leaks"]}'
            )
            self.capture_log.append(
                f'<span style="color:#4fc3f7;">[ℹ️]</span>'
                f' Найдено комментариев разработчиков: {stats["comments"]}'
            )
            self.capture_log.append(
                f'<span style="color:#81c784;">[📂]</span>'
                f' Обнаружены скрытые/технические пути: {stats["hidden_paths"]}'
            )

    # Secret detection is delegated to the shared SecretScanner (single source
    # of truth) so the Capture tab's leak count matches the API / Security tabs.
    _secret_scanner = SecretScanner()
    _COMMENT_RE = re.compile(r'<!--(.{8,}?)-->', re.DOTALL)
    _HIDDEN_RE  = re.compile(
        r'(?:href|src|action)=["\'][^"\']*'
        r'(?:/admin|/api/|/debug|/test|/staging|\.env|/config'
        r'|/internal|/swagger|/graphql|/phpmyadmin|/wp-admin|/manage|/console)',
        re.IGNORECASE,
    )

    def _analyse_capture_files(self, files: list) -> dict:
        key_leaks   = 0
        comments    = 0
        hidden_paths = 0
        seen_keys   : set = set()
        seen_paths  : set = set()
        for filepath in files:
            try:
                text = Path(filepath).read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            for finding in self._secret_scanner.scan_text(text, filepath):
                token = finding['match']
                if token not in seen_keys:
                    seen_keys.add(token)
                    key_leaks += 1
            comments += len(self._COMMENT_RE.findall(text))
            for m in self._HIDDEN_RE.finditer(text):
                hit = m.group(0)
                if hit not in seen_paths:
                    seen_paths.add(hit)
                    hidden_paths += 1
        return {'key_leaks': key_leaks, 'comments': comments, 'hidden_paths': hidden_paths}
