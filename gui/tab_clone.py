"""Clone Frontend tab — turns a captured site into a self-contained offline copy.

Mixin folded into MainWindow; uses _browse, _set_busy, _start_task and
_active_cloner (for cancellation).
"""

import os
from pathlib import Path

from PyQt5.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QProgressBar,
    QVBoxLayout, QWidget,
)

from core.frontend_cloner import FrontendCloner
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from gui.workers import _CloneWorker


class CloneTabMixin:
    """Builds and drives the Clone Frontend tab."""

    def _build_clone_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Cloner Settings")
        g = QVBoxLayout()
        g.setSpacing(8)

        # Source directory
        row_src = QHBoxLayout()
        row_src.addWidget(QLabel("Source Dir:"))
        self.clone_src = QLineEdit()
        self.clone_src.setPlaceholderText(
            "Folder with captured HTML files and site_map.json"
        )
        btn_browse_src = StyledButton("Browse…", style='secondary')
        btn_browse_src.setFixedWidth(90)
        btn_browse_src.clicked.connect(lambda: self._browse(self.clone_src))
        row_src.addWidget(self.clone_src)
        row_src.addWidget(btn_browse_src)
        g.addLayout(row_src)

        # Output directory (optional)
        row_out = QHBoxLayout()
        row_out.addWidget(QLabel("Output Dir:"))
        self.clone_out = QLineEdit()
        self.clone_out.setPlaceholderText(
            "Leave blank to auto-create <source>_cloned/ next to source"
        )
        btn_browse_out = StyledButton("Browse…", style='secondary')
        btn_browse_out.setFixedWidth(90)
        btn_browse_out.clicked.connect(lambda: self._browse(self.clone_out))
        row_out.addWidget(self.clone_out)
        row_out.addWidget(btn_browse_out)
        g.addLayout(row_out)

        # Action row
        row_act = QHBoxLayout()
        row_act.addStretch()
        self.btn_clone_run = StyledButton("Clone Frontend")
        self.btn_clone_run.clicked.connect(self._run_clone)
        self.btn_clone_stop = StyledButton("Stop", style='secondary')
        self.btn_clone_stop.setEnabled(False)
        self.btn_clone_stop.clicked.connect(self._stop_clone)
        row_act.addWidget(self.btn_clone_run)
        row_act.addWidget(self.btn_clone_stop)
        g.addLayout(row_act)

        grp.setLayout(g)
        layout.addWidget(grp)

        # Log / results
        res_grp = SectionGroupBox("Clone Log")
        res_layout = QVBoxLayout()

        hdr_row = QHBoxLayout()
        self.clone_status_lbl = QLabel("Ready")
        self.clone_status_lbl.setStyleSheet(
            "color:#4fc3f7; font-family:Consolas; font-size:12px; padding:2px 0;"
        )
        self.clone_progress = QProgressBar()
        self.clone_progress.setMaximumHeight(14)
        self.clone_progress.setVisible(False)
        self.clone_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555; border-radius: 3px;
                background: #2d2d2d; text-align: center; color: transparent;
            }
            QProgressBar::chunk { background: #0078d4; border-radius: 2px; }
        """)
        hdr_row.addWidget(self.clone_status_lbl)
        hdr_row.addWidget(self.clone_progress, 1)
        res_layout.addLayout(hdr_row)

        self.clone_log = ResultsDisplay()
        res_layout.addWidget(self.clone_log)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.btn_clone_open = StyledButton("Open Output Folder", style='secondary')
        self.btn_clone_open.setEnabled(False)
        self.btn_clone_open.clicked.connect(self._open_clone_output)
        btn_row.addWidget(self.btn_clone_open)
        res_layout.addLayout(btn_row)

        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_clone(self):
        src = self.clone_src.text().strip()
        if not src:
            QMessageBox.warning(self, "Clone Frontend", "Select a source directory first.")
            return
        if not Path(src).is_dir():
            QMessageBox.warning(self, "Clone Frontend",
                                f"Source directory not found:\n{src}")
            return

        out = self.clone_out.text().strip()
        if not out:
            out = str(Path(src).parent / (Path(src).name + '_cloned'))

        profile = self.settings.get('user_agent_profile', 'chrome_windows')

        self.clone_log.clear()
        self.clone_log.append_info(f"Source : {src}")
        self.clone_log.append_info(f"Output : {out}")
        self.clone_status_lbl.setText("Starting…")
        self.clone_progress.setRange(0, 0)
        self.clone_progress.setVisible(True)
        self.btn_clone_run.setEnabled(False)
        self.btn_clone_stop.setEnabled(True)
        self.btn_clone_open.setEnabled(False)
        self._set_busy(True)

        cloner = FrontendCloner()
        cloner.configure(src, out, profile=profile)
        self._active_cloner = cloner

        worker = _CloneWorker(cloner)
        self._start_task(
            worker,
            on_finished=self._on_clone_done,
            on_error=lambda e: (self._reset_clone_buttons(),
                                self._set_busy(False),
                                self.clone_progress.setVisible(False),
                                self.clone_status_lbl.setText("Error"),
                                QMessageBox.critical(self, "Clone Error", e)),
            signals=[
                (worker.log_message, self._on_clone_log),
                (worker.progress,    self._on_clone_progress),
            ],
        )

    def _stop_clone(self):
        if getattr(self, '_active_cloner', None):
            self._active_cloner.cancel()
            self.clone_log.append_warning("Stopping clone…")
        self.btn_clone_stop.setEnabled(False)

    def _reset_clone_buttons(self):
        self._active_cloner = None
        self.btn_clone_run.setEnabled(True)
        self.btn_clone_stop.setEnabled(False)

    def _on_clone_log(self, msg: str):
        m = msg.strip()
        if 'Ошибка' in m or 'Error' in m:
            self.clone_log.append_error(msg)
        elif m.startswith('Готово') or m.startswith('[OK]'):
            self.clone_log.append_success(msg)
        elif m.startswith('[') and ']' in m:
            self.clone_log.append(
                f'<span style="color:#888; font-family:Consolas;">{msg}</span>'
            )
        else:
            self.clone_log.append_info(msg)

    def _on_clone_progress(self, current: int, total: int):
        if total > 0:
            self.clone_progress.setRange(0, total)
            self.clone_progress.setValue(current)
            self.clone_status_lbl.setText(f"Page {current}/{total}")
        else:
            self.clone_progress.setRange(0, 0)

    def _on_clone_done(self, result: dict):
        self._set_busy(False)
        self._reset_clone_buttons()
        self.clone_progress.setVisible(False)
        status = result.get('status', '')
        pages  = result.get('pages_processed', 0)
        assets = result.get('assets_downloaded', 0)
        failed = result.get('failed', [])
        out    = result.get('output_dir', '')

        if result.get('cancelled'):
            self.clone_status_lbl.setText(f"Cancelled — {pages} page(s) done")
            self.clone_log.append_warning(
                f"Clone cancelled — {pages} page(s), {assets} asset(s) saved"
            )
            if out:
                self._clone_output_dir = out
                self.btn_clone_open.setEnabled(True)
        elif 'Success' in status or pages > 0:
            self.clone_status_lbl.setText(f"Done — {pages} page(s), {assets} asset(s)")
            self.clone_log.append_success(
                f"Done — {pages} page(s), {assets} asset(s) downloaded"
            )
            if failed:
                self.clone_log.append_warning(
                    f"{len(failed)} asset(s) failed to download"
                )
            if out:
                self.clone_log.append_info(f"Output folder: {out}")
                self._clone_output_dir = out
                self.btn_clone_open.setEnabled(True)
        else:
            self.clone_status_lbl.setText("Failed")
            self.clone_log.append_error(f"Status: {status}")
            if failed:
                for f in failed[:10]:
                    self.clone_log.append_warning(f"  failed: {f}")

    def _open_clone_output(self):
        d = getattr(self, '_clone_output_dir', None)
        if d and Path(d).exists():
            try:
                os.startfile(d)
            except Exception:
                pass
