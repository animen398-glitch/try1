"""Deep Crawl (Scrapy) — external tab plugin.

Demonstrates the plugin-ready architecture end to end with a real, optional,
heavy third-party tool: a ``register(manager)`` hook plus a standalone QWidget
factory that drives core.scrapy_crawler through the host window's shared helpers
(``window._run_async`` / ``window.settings`` / ``window._set_busy``).

Why a plugin and not a built-in tab: Scrapy is optional and heavyweight, so it
belongs outside the core GUI. The module imports cleanly even when Scrapy is not
installed (the crawl runs in a child process; nothing here imports ``scrapy``),
so the tab always appears and explains how to enable the feature.
"""

from qtpy.QtCore import Qt
from qtpy.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
    QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.scrapy_crawler import ScrapyCrawler
from gui.plugin_manager import TabPlugin
from gui.ui_components import SectionGroupBox, StyledButton

_COLUMNS = ["URL", "Status", "Title", "Depth", "Size"]


class _ScrapyTab(QWidget):
    """Standalone tab widget; reaches shared runner helpers via ``window``."""

    def __init__(self, window):
        super().__init__()
        self._window = window
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        grp = SectionGroupBox("Deep Crawl (Scrapy, subprocess)")
        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://example.com")
        self.url.returnPressed.connect(self._run)
        row.addWidget(self.url, stretch=1)

        row.addWidget(QLabel("Pages:"))
        self.max_pages = QSpinBox()
        self.max_pages.setRange(1, 1000)
        self.max_pages.setValue(50)
        row.addWidget(self.max_pages)

        row.addWidget(QLabel("Depth:"))
        self.depth = QSpinBox()
        self.depth.setRange(0, 10)
        self.depth.setValue(2)
        row.addWidget(self.depth)

        self.btn = StyledButton("Crawl")
        self.btn.clicked.connect(self._run)
        row.addWidget(self.btn)
        grp.setLayout(row)
        layout.addWidget(grp)

        self.status = QLabel()
        self.status.setStyleSheet(
            "color:#4fc3f7; font-family:Consolas; font-size:12px; padding:2px 0;")
        layout.addWidget(self.status)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, len(_COLUMNS)):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        layout.addWidget(self.table, stretch=1)

        if ScrapyCrawler.is_available():
            self.status.setText("Ready")
        else:
            self.status.setText('Scrapy не установлен — pip install "scrapy>=2.11,<3"')
            self.btn.setEnabled(False)

    def _run(self):
        url = self.url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return
        if not ScrapyCrawler.is_available():
            QMessageBox.warning(self, "Scrapy", 'Установите scrapy: pip install "scrapy>=2.11,<3"')
            return
        self.table.setRowCount(0)
        self.status.setText(f"Краулинг: {url} …")
        self.btn.setEnabled(False)
        self._window._set_busy(True)

        crawler = ScrapyCrawler(
            max_pages=self.max_pages.value(),
            depth=self.depth.value(),
        )
        self._window._run_async(lambda u=url: crawler.crawl(u), self._on_done)

    def _on_done(self, result: dict):
        self._window._set_busy(False)
        self.btn.setEnabled(True)

        if result.get('status') != 'Success':
            self.status.setText(f"Ошибка: {result.get('error', 'unknown')}")
            return

        items = result.get('items', [])
        for it in items:
            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [
                it.get('url', ''),
                str(it.get('status', '')),
                it.get('title', ''),
                str(it.get('depth', '')),
                self._fmt_size(it.get('size', 0)),
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                if col in (1, 3, 4):
                    item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(r, col, item)

        note = " (обрезано по лимиту/таймауту)" if result.get('truncated') else ""
        self.status.setText(f"Страниц пройдено: {result.get('pages', 0)}{note}")
        try:
            self._window._save_target(self.url.text().strip())
        except Exception:
            pass

    @staticmethod
    def _fmt_size(n: int) -> str:
        n = float(n or 0)
        for unit in ('B', 'KB', 'MB'):
            if n < 1024:
                return f"{n:.0f}{unit}" if unit == 'B' else f"{n:.1f}{unit}"
            n /= 1024
        return f"{n:.1f}GB"


def register(manager) -> None:
    manager.register(TabPlugin("scrapy_crawl", "Deep Crawl (Scrapy)",
                               lambda window: _ScrapyTab(window)))
