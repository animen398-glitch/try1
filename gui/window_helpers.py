"""gui/window_helpers.py

Small cross-cutting helpers shared by the tab mixins: path/size utilities,
archiving, folder/file pickers, the busy-state toggle, and the target-history
wrapper. Folded into MainWindow as a mixin so every tab reaches them as
``self._fmt_size(...)``, ``self._browse(...)``, etc.

The host window is expected to provide:
  • ``self.settings``     dict — read by _make_archive (compression_format)
  • ``self.progress_bar`` / ``self.status_bar`` — driven by _set_busy
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from qtpy.QtWidgets import QFileDialog, QLineEdit

from core import config
from utils.file_compression import FileCompressor


class WindowHelpersMixin:
    """Shared path/UI helpers used across the tab mixins."""

    @staticmethod
    def _domain_slug(url: str) -> str:
        netloc = urlparse(url).netloc or url.split('/')[0]
        return netloc.replace('www.', '').replace(':', '_').strip('.') or 'unknown'

    @staticmethod
    def _folder_size(path: Path) -> int:
        return sum(f.stat().st_size for f in path.rglob('*') if f.is_file())

    @staticmethod
    def _fmt_size(nbytes: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if nbytes < 1024:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024
        return f"{nbytes:.2f} TB"

    def _make_archive(self, source_dir: Path, domain: str, suffix: str) -> Optional[str]:
        # Honour the "auto-archive" setting — off means no archive is produced.
        if not self.settings.get('auto_compress', False):
            return None
        if not source_dir.exists() or not any(source_dir.rglob('*')):
            return None
        fmt = self.settings.get('compression_format', 'zip')
        name = f"{domain}_{datetime.now().strftime('%Y%m%d')}_{suffix}.{fmt}"
        out = str(source_dir.parent / name)
        try:
            return FileCompressor.to_rar(source_dir, out) if fmt == 'rar' else FileCompressor.to_zip(source_dir, out)
        except Exception:
            return None

    def _set_busy(self, busy: bool):
        self.progress_bar.setVisible(busy)
        if busy:
            self.progress_bar.setRange(0, 0)
            self.status_bar.showMessage("Выполняется...")
        else:
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage("Готов")

    def _browse(self, line_edit: QLineEdit):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку", line_edit.text())
        if path:
            line_edit.setText(path)

    def _browse_file(self, line_edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", line_edit.text())
        if path:
            line_edit.setText(path)

    def _save_target(self, url: str):
        config.save_target(url)
