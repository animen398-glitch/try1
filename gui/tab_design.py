"""Design Lab tab — colour palette / typography extraction and version diff.

Mixin folded into MainWindow; uses shared helpers (_browse, _set_busy,
_run_async).
"""

import json
from pathlib import Path

from PyQt5.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QVBoxLayout, QWidget,
)

from core.design_analyzer import DesignAnalyzer
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton


class DesignTabMixin:
    """Builds and drives the Design Lab tab."""

    def _build_design_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)

        src_grp = SectionGroupBox("Источник анализа")
        src_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Директория с захваченными файлами:"))
        self.design_dir = QLineEdit(self.settings.get('output_dir', ''))
        btn_browse = StyledButton("...", style='secondary')
        btn_browse.setMaximumWidth(40)
        btn_browse.clicked.connect(lambda: self._browse(self.design_dir))
        row1.addWidget(self.design_dir)
        row1.addWidget(btn_browse)
        src_layout.addLayout(row1)

        row2 = QHBoxLayout()
        btn_run = StyledButton("Запустить анализ")
        btn_run.clicked.connect(self._run_design_analysis)
        btn_load = StyledButton("Загрузить palette.json", style='secondary')
        btn_load.clicked.connect(self._load_palette_from_dir)
        self.design_stats_label = QLabel("")
        self.design_stats_label.setStyleSheet("color:#888; font-size:11px; padding-left:8px;")
        row2.addWidget(btn_run)
        row2.addWidget(btn_load)
        row2.addStretch()
        row2.addWidget(self.design_stats_label)
        src_layout.addLayout(row2)

        src_grp.setLayout(src_layout)
        layout.addWidget(src_grp)

        results_row = QHBoxLayout()

        colors_grp = SectionGroupBox("Цветовая палитра")
        cl = QVBoxLayout()
        self.design_colors = ResultsDisplay()
        cl.addWidget(self.design_colors)
        colors_grp.setLayout(cl)

        fonts_grp = SectionGroupBox("Типографика")
        fl = QVBoxLayout()
        self.design_fonts = ResultsDisplay()
        fl.addWidget(self.design_fonts)
        fonts_grp.setLayout(fl)

        results_row.addWidget(colors_grp, 3)
        results_row.addWidget(fonts_grp, 2)
        layout.addLayout(results_row)

        cmp_grp = SectionGroupBox("Сравнение версий (анализ изменений)")
        cmp_layout = QVBoxLayout()

        rowa = QHBoxLayout()
        rowa.addWidget(QLabel("Папка A:"))
        self.design_cmp_a = QLineEdit()
        self.design_cmp_a.setPlaceholderText("Старая версия (папка с захваченными файлами)")
        btn_browse_a = StyledButton("...", style='secondary')
        btn_browse_a.setMaximumWidth(40)
        btn_browse_a.clicked.connect(lambda: self._browse(self.design_cmp_a))
        rowa.addWidget(self.design_cmp_a)
        rowa.addWidget(btn_browse_a)
        cmp_layout.addLayout(rowa)

        rowb = QHBoxLayout()
        rowb.addWidget(QLabel("Папка B:"))
        self.design_cmp_b = QLineEdit()
        self.design_cmp_b.setPlaceholderText("Новая версия (папка с захваченными файлами)")
        btn_browse_b = StyledButton("...", style='secondary')
        btn_browse_b.setMaximumWidth(40)
        btn_browse_b.clicked.connect(lambda: self._browse(self.design_cmp_b))
        rowb.addWidget(self.design_cmp_b)
        rowb.addWidget(btn_browse_b)
        cmp_layout.addLayout(rowb)

        btn_cmp = StyledButton("Сравнить")
        btn_cmp.clicked.connect(self._run_design_compare)
        cmp_layout.addWidget(btn_cmp)

        self.design_diff = ResultsDisplay()
        cmp_layout.addWidget(self.design_diff)

        cmp_grp.setLayout(cmp_layout)
        layout.addWidget(cmp_grp)

        self._design_show_placeholder()
        return w

    def _run_design_compare(self):
        path_a = self.design_cmp_a.text().strip()
        path_b = self.design_cmp_b.text().strip()
        if not path_a or not path_b:
            QMessageBox.warning(self, "Ошибка", "Укажите обе папки для сравнения")
            return

        self.design_diff.clear()
        self.design_diff.append_info(f"Сравниваю:\n  A: {path_a}\n  B: {path_b}")
        self._set_busy(True)

        analyzer = DesignAnalyzer()
        analyzer.set_progress_callback(lambda msg: self.design_diff.append_info(msg))
        self._run_async(
            lambda: analyzer.compare_versions(path_a, path_b),
            self._on_design_compare_done,
        )

    def _on_design_compare_done(self, result: dict):
        self._set_busy(False)
        status = result.get('status', '')
        if status != 'Success':
            self.design_diff.append_error(f"Ошибка: {status}")
            return

        s = result.get('summary', {})
        self.design_diff.append_success(
            f"Added: {s.get('added', 0)}  |  "
            f"Modified: {s.get('modified', 0)}  |  "
            f"Removed: {s.get('removed', 0)}  |  "
            f"Unchanged: {s.get('unchanged', 0)}"
        )
        for f in result.get('added', [])[:25]:
            self.design_diff.append(f'<span style="color:#81c784;">[+]</span> {f}')
        for f in result.get('modified', [])[:25]:
            self.design_diff.append(f'<span style="color:#ffb74d;">[~]</span> {f}')
        for f in result.get('removed', [])[:25]:
            self.design_diff.append(f'<span style="color:#e57373;">[-]</span> {f}')

    def _run_design_analysis(self):
        source = self.design_dir.text().strip()
        if not source:
            QMessageBox.warning(self, "Ошибка", "Укажите директорию")
            return
        self.design_colors.clear()
        self.design_fonts.clear()
        self.design_colors.append_info(f"Анализирую: {source}")
        self._set_busy(True)

        analyzer = DesignAnalyzer()
        analyzer.configure(source)
        analyzer.set_progress_callback(lambda msg: self.design_colors.append_info(msg))

        self._run_async(analyzer.analyze, self._on_design_done)

    def _on_design_done(self, result: dict):
        self._set_busy(False)
        status = result.get('status', '')
        if status == 'Success':
            self._render_palette(result)
            stats = result.get('stats', {})
            self.design_stats_label.setText(
                f"Цветов: {stats.get('total_colors', 0)}  |  "
                f"Шрифтов: {stats.get('total_fonts', 0)}  |  "
                f"Файлов: {stats.get('css_files', 0)} CSS, {stats.get('html_files', 0)} HTML"
            )
        elif 'Warning' in status:
            self._design_show_placeholder()
            self.design_colors.append_warning(status)
        else:
            self.design_colors.append_error(f"Ошибка: {status}")

    def _load_palette_from_dir(self):
        source = self.design_dir.text().strip()
        if not source:
            QMessageBox.warning(self, "Ошибка", "Укажите директорию")
            return
        palette_path = Path(source) / 'ui_palette.json'
        if not palette_path.exists():
            self._design_show_placeholder()
            return
        try:
            data = json.loads(palette_path.read_text(encoding='utf-8'))
            self._render_palette(data)
            stats = data.get('stats', {})
            self.design_stats_label.setText(
                f"Цветов: {stats.get('total_colors', 0)}  |  "
                f"Шрифтов: {stats.get('total_fonts', 0)}"
            )
        except Exception as e:
            self.design_colors.append_error(f"Ошибка чтения palette.json: {e}")

    def _render_palette(self, data: dict):
        colors = data.get('colors', [])
        fonts = data.get('fonts', [])

        if colors:
            rows = []
            for c in colors:
                ctype = c.get('type', '')
                val = c.get('value', '')
                if ctype == 'hex':
                    bg = val
                    display = f'<span style="color:#d4d4d4;">{val}</span>'
                elif ctype == 'rgb':
                    bg = c.get('hex', '#888888')
                    display = (
                        f'<span style="color:#d4d4d4;">{val}</span>'
                        f'<span style="color:#555; font-size:10px;">&nbsp;&nbsp;&#8801;&nbsp;{bg}</span>'
                    )
                else:
                    bg = '#666666'
                    display = f'<span style="color:#d4d4d4;">{val}</span>'

                rows.append(
                    f'<tr>'
                    f'<td style="padding:3px 6px;">'
                    f'<span style="background-color:{bg}; padding:4px 14px; '
                    f'font-size:1px; color:{bg};">&nbsp;</span>'
                    f'</td>'
                    f'<td style="padding:3px 10px; font-family:Consolas,monospace; font-size:11px;">'
                    f'{display}</td>'
                    f'<td style="padding:3px 4px; color:#555; font-size:10px;">[{ctype}]</td>'
                    f'</tr>'
                )
            colors_html = (
                '<table border="0" cellspacing="1" cellpadding="1" '
                'style="font-family:Consolas,monospace;">'
                + ''.join(rows)
                + '</table>'
            )
        else:
            colors_html = (
                '<p style="color:#888; font-style:italic; '
                'font-family:Consolas,monospace; padding:8px;">Цвета не найдены</p>'
            )
        self.design_colors.setHtml(colors_html)

        if fonts:
            items = ''.join(
                f'<p style="margin:4px 0;">'
                f'<span style="color:#4fc3f7; font-size:13px;">&#9670;</span>&nbsp;'
                f'<span style="color:#81c784; font-family:Consolas,monospace; '
                f'font-size:12px;">{font}</span>'
                f'</p>'
                for font in fonts
            )
            fonts_html = f'<div style="padding:4px;">{items}</div>'
        else:
            fonts_html = (
                '<p style="color:#888; font-style:italic; '
                'font-family:Consolas,monospace; padding:8px;">Шрифты не найдены</p>'
            )
        self.design_fonts.setHtml(fonts_html)

    def _design_show_placeholder(self):
        msg = (
            '<p style="color:#666; font-style:italic; '
            'font-family:Consolas,monospace; font-size:11px; padding:12px;">'
            'Захватите сайт или запустите анализ для отображения палитры</p>'
        )
        self.design_colors.setHtml(msg)
        self.design_fonts.setHtml(msg)
        self.design_stats_label.setText("")
