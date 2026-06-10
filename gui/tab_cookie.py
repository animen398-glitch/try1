"""Cookie Security Audit tab — inspects a site's cookies for HttpOnly /
Secure / SameSite and rates each one.

Mixin folded into MainWindow; uses shared helpers (_set_busy, _run_async).
"""

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.cookie_auditor import CookieAuditor
from gui.ui_components import SectionGroupBox, StyledButton


_VERDICT_COLORS = {
    'Strong':   '#81c784',
    'Moderate': '#ffb74d',
    'Weak':     '#e57373',
}


class CookieAuditTabMixin:
    """Builds and drives the Cookie Security Audit tab."""

    COOKIE_COLUMNS = ["Cookie", "HttpOnly", "Secure", "SameSite", "Verdict"]

    def _build_cookie_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Цель аудита")
        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.cookie_url = QLineEdit()
        self.cookie_url.setPlaceholderText("https://example.com")
        self.cookie_url.returnPressed.connect(self._run_cookie_audit)
        self.btn_cookie_scan = StyledButton("Audit Cookies")
        self.btn_cookie_scan.clicked.connect(self._run_cookie_audit)
        row.addWidget(self.cookie_url)
        row.addWidget(self.btn_cookie_scan)
        grp.setLayout(row)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Cookie Security")
        res_layout = QVBoxLayout()
        self.cookie_status = QLabel("Ready")
        self.cookie_status.setStyleSheet(
            "color:#4fc3f7; font-family:Consolas; font-size:12px; padding:2px 0;"
        )
        res_layout.addWidget(self.cookie_status)

        self.cookie_table = QTableWidget(0, len(self.COOKIE_COLUMNS))
        self.cookie_table.setHorizontalHeaderLabels(self.COOKIE_COLUMNS)
        self.cookie_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.cookie_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cookie_table.verticalHeader().setVisible(False)
        self.cookie_table.setAlternatingRowColors(True)
        hdr = self.cookie_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, len(self.COOKIE_COLUMNS)):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        res_layout.addWidget(self.cookie_table)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp, stretch=1)
        return w

    def _run_cookie_audit(self):
        url = self.cookie_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return
        self.cookie_table.setRowCount(0)
        self.cookie_status.setText(f"Аудит: {url} …")
        self.btn_cookie_scan.setEnabled(False)
        self._set_busy(True)

        auditor = CookieAuditor(
            profile=self.settings.get('user_agent_profile', 'chrome_windows')
        )
        self._run_async(lambda u=url: auditor.audit(u), self._on_cookie_done)

    def _on_cookie_done(self, result: dict):
        self._set_busy(False)
        self.btn_cookie_scan.setEnabled(True)

        if result.get('status') != 'Success':
            self.cookie_status.setText(f"Ошибка: {result.get('error', 'unknown')}")
            return

        cookies = result.get('cookies', [])
        self._populate_cookie_table(cookies)

        total = result.get('total', 0)
        weak = result.get('weak', 0)
        if total == 0:
            self.cookie_status.setText(
                result.get('note', 'Куки не обнаружены на этом ответе.')
            )
        else:
            self.cookie_status.setText(
                f"Куки: {total}  |  слабых: {weak}  |  HTTP {result.get('http_status', '?')}"
            )

    def _populate_cookie_table(self, cookies: list):
        check = {True: '✓', False: '✗'}
        self.cookie_table.setRowCount(0)
        for c in cookies:
            r = self.cookie_table.rowCount()
            self.cookie_table.insertRow(r)
            values = [
                c.get('name', ''),
                check[bool(c.get('httponly'))],
                check[bool(c.get('secure'))],
                str(c.get('samesite', '—')),
                c.get('verdict', ''),
            ]
            tooltip = '\n'.join(c.get('issues', [])) or 'No issues — securely configured'
            for col, val in enumerate(values):
                item = QTableWidgetItem(str(val))
                item.setToolTip(tooltip)
                if col in (1, 2, 3, 4):
                    item.setTextAlignment(Qt.AlignCenter)
                # Flag-presence columns: green tick / red cross.
                if col in (1, 2):
                    item.setForeground(
                        QColor('#81c784') if val == '✓' else QColor('#e57373')
                    )
                if col == 4:  # Verdict
                    item.setForeground(QColor(_VERDICT_COLORS.get(val, '#d4d4d4')))
                self.cookie_table.setItem(r, col, item)
