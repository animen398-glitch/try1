"""API Key Scanner tab — scans a target page for leaked credentials.

Mixin folded into MainWindow; relies on shared helpers (_run_async,
_set_busy, _save_target, self.settings).
"""

from qtpy.QtWidgets import QHBoxLayout, QLineEdit, QMessageBox, QVBoxLayout, QWidget

from core.api_key_extractor import ApiKeyExtractor
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton


class ApiTabMixin:
    """Builds and drives the API Key Scanner tab."""

    def _build_api_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Целевой URL")
        row = QHBoxLayout()
        self.api_url = QLineEdit()
        self.api_url.setPlaceholderText("https://example.com")
        self.api_url.returnPressed.connect(self._run_api_scan)
        btn = StyledButton("Сканировать")
        btn.clicked.connect(self._run_api_scan)
        row.addWidget(self.api_url)
        row.addWidget(btn)
        grp.setLayout(row)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Результаты")
        res_layout = QVBoxLayout()
        self.api_results = ResultsDisplay()
        res_layout.addWidget(self.api_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_api_scan(self):
        url = self.api_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Введите URL")
            return
        self.api_results.clear()
        self.api_results.append_info(f"Начинаю сканирование: {url}")
        self._set_busy(True)

        extractor = ApiKeyExtractor()
        extractor.set_target_url(url)
        extractor.set_profile(self.settings.get('user_agent_profile', 'chrome_windows'))
        self._run_async(extractor.run_extraction, self._on_api_done)

    def _on_api_done(self, result: dict):
        self._set_busy(False)
        status = result.get('status', '')
        if status == 'Success':
            found = result.get('keys_found', 0)
            self.api_results.append_success(f"Статус: {status} | Найдено: {found}")
            details = result.get('details', {})
            if details:
                for key_type, keys in details.items():
                    self.api_results.append_warning(f"[{key_type}]:")
                    for k in keys:
                        self.api_results.append(f"  • {k}")
            else:
                self.api_results.append_info("Утечек не обнаружено")
        else:
            self.api_results.append_error(f"Ошибка: {status}")
        self._save_target(self.api_url.text().strip())
