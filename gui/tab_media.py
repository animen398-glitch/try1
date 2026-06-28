"""Media tabs — Video Downloader (yt-dlp) and Image Extractor.

Both are mixins folded into MainWindow and share its helpers
(_domain_slug, _set_busy, _run_async, _folder_size, _fmt_size,
_make_archive, _save_video_log).
"""

from datetime import datetime
from pathlib import Path

from qtpy.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QVBoxLayout, QWidget,
)

from core.cookie_auditor import CookieFileError, describe_cookies_txt
from gui.constants import LIVE_TEST_OUTPUT
from gui.ui_components import ResultsDisplay, SectionGroupBox, StyledButton
from utils.image_processor import ImageExtractor
from utils.video_processor import VideoDownloader

# Quality presets surfaced in the Video Downloader dropdown.
_VIDEO_QUALITIES = ['4k', '1440p', '1080p', '720p', 'best', 'audio']


class VideoTabMixin:
    """Builds and drives the Video Downloader tab."""

    def _build_video_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Загрузка видео (yt-dlp)")
        g = QVBoxLayout()

        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.video_url = QLineEdit()
        self.video_url.setPlaceholderText("https://youtube.com/watch?v=...")
        self.video_url.returnPressed.connect(self._run_video)
        row.addWidget(self.video_url)
        g.addLayout(row)

        opts = QHBoxLayout()
        opts.addWidget(QLabel("Качество:"))
        self.video_quality = QComboBox()
        self.video_quality.addItems(_VIDEO_QUALITIES)
        self.video_quality.setCurrentText('1080p')
        self.video_quality.setToolTip(
            "4K/1080p объединяют раздельные видео+аудио дорожки через ffmpeg\n"
            "(без ffmpeg качество ограничивается прогрессивным потоком)."
        )
        opts.addWidget(self.video_quality)
        opts.addSpacing(12)
        opts.addWidget(QLabel("Cookies:"))
        self.video_cookies = QLineEdit()
        self.video_cookies.setPlaceholderText("cookies.txt для авторизованного скачивания (опционально)")
        btn_ck = StyledButton("...", style='secondary')
        btn_ck.setMaximumWidth(40)
        btn_ck.clicked.connect(lambda: self._browse_file(self.video_cookies))
        opts.addWidget(self.video_cookies)
        opts.addWidget(btn_ck)
        g.addLayout(opts)

        btn_dl = StyledButton("Скачать", style='success')
        btn_dl.clicked.connect(self._run_video)
        g.addWidget(btn_dl)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Статус")
        res_layout = QVBoxLayout()
        self.video_results = ResultsDisplay()
        res_layout.addWidget(self.video_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_video(self):
        url = self.video_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return

        domain = self._domain_slug(url)
        out_path = LIVE_TEST_OUTPUT / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_video"

        quality = self.video_quality.currentText()
        cookies = self.video_cookies.text().strip() or None
        try:
            cookie_summary = describe_cookies_txt(cookies) if cookies else None
        except CookieFileError as e:
            QMessageBox.warning(self, "Invalid cookies.txt", str(e))
            return

        self.video_results.clear()
        if not VideoDownloader.is_available():
            self.video_results.append_error(
                "yt-dlp не найден — загрузка видео недоступна. "
                "Установите: pip install yt-dlp"
            )
            return
        self.video_results.append_info(f"Загружаю [{quality}]: {url}")
        self.video_results.append_info(f"Директория: {out_path}")
        if cookie_summary:
            self.video_results.append_info(f"Cookies: {cookie_summary}")
        if quality in ('4k', '1440p', '1080p') and not VideoDownloader.has_ffmpeg():
            self.video_results.append_warning(
                "ffmpeg не найден — будет использован прогрессивный поток "
                "(меньшее качество). Установите ffmpeg для полного 4K/1080p."
            )
        self._set_busy(True)

        dl = VideoDownloader(quality=quality, cookies=cookies)

        def _on_done(result, _p=out_path, _u=url):
            self._on_video_done(result, _p, _u)

        self._run_async(lambda: dl.download_video(url, out_path), _on_done)

    def _on_video_done(self, result: dict, out_path: Path, url: str):
        self._set_busy(False)
        status = result.get('status', '')
        if status == 'Success':
            self.video_results.append_success("Загрузка завершена")
            self.video_results.append_info(f"Директория: {out_path}")
            if 'output' in result:
                self.video_results.append(result['output'][:500])
        else:
            self.video_results.append_error(f"Ошибка: {status}")
        self._save_video_log(out_path, url, status)


class ImageTabMixin:
    """Builds and drives the Image Extractor tab."""

    def _build_image_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = SectionGroupBox("Извлечение изображений")
        g = QVBoxLayout()

        row = QHBoxLayout()
        row.addWidget(QLabel("URL:"))
        self.image_url = QLineEdit()
        self.image_url.setPlaceholderText("https://example.com  (или ссылка на пост Instagram)")
        self.image_url.returnPressed.connect(self._run_images)
        row.addWidget(self.image_url)
        g.addLayout(row)

        ck_row = QHBoxLayout()
        ck_row.addWidget(QLabel("Cookies:"))
        self.image_cookies = QLineEdit()
        self.image_cookies.setPlaceholderText(
            "cookies.txt — для Instagram/закрытых галерей (опционально)"
        )
        btn_ck = StyledButton("...", style='secondary')
        btn_ck.setMaximumWidth(40)
        btn_ck.clicked.connect(lambda: self._browse_file(self.image_cookies))
        ck_row.addWidget(self.image_cookies)
        ck_row.addWidget(btn_ck)
        g.addLayout(ck_row)

        hint = QLabel(
            "Оригинальное разрешение без водяных знаков; Instagram/соцсети "
            "скачиваются через yt-dlp."
        )
        hint.setStyleSheet("color:#888; font-size:10px;")
        g.addWidget(hint)

        btn_ex = StyledButton("Извлечь изображения")
        btn_ex.clicked.connect(self._run_images)
        g.addWidget(btn_ex)
        grp.setLayout(g)
        layout.addWidget(grp)

        res_grp = SectionGroupBox("Найденные изображения")
        res_layout = QVBoxLayout()
        self.image_results = ResultsDisplay()
        res_layout.addWidget(self.image_results)
        res_grp.setLayout(res_layout)
        layout.addWidget(res_grp)
        return w

    def _run_images(self):
        url = self.image_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Ошибка", "Укажите URL")
            return

        domain = self._domain_slug(url)
        out_path = LIVE_TEST_OUTPUT / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_images"

        self.image_results.clear()
        self.image_results.append_info(f"Сканирую: {url}")
        self.image_results.append_info(f"Директория: {out_path}")
        self._set_busy(True)

        cookies = self.image_cookies.text().strip() or None
        try:
            cookie_summary = describe_cookies_txt(cookies) if cookies else None
        except CookieFileError as e:
            self._set_busy(False)
            QMessageBox.warning(self, "Invalid cookies.txt", str(e))
            return
        if cookie_summary:
            self.image_results.append_info(f"Cookies: {cookie_summary}")
        ex = ImageExtractor(
            profile=self.settings.get('user_agent_profile', 'chrome_windows'),
            cookies=cookies,
        )
        ex.set_progress_callback(lambda msg: self.image_results.append_info(msg))

        def _on_done(result, _p=out_path, _d=domain):
            self._on_images_done(result, _p, _d)

        self._run_async(lambda: ex.extract_images(url, out_path), _on_done)

    def _on_images_done(self, result: dict, out_path: Path, domain: str):
        self._set_busy(False)
        found = result.get('found', 0)
        downloaded = result.get('downloaded', 0)
        self.image_results.append_success(f"Найдено: {found} | Загружено: {downloaded}")
        self.image_results.append_info(
            f"Отфильтровано — дубликатов: {result.get('duplicates', 0)} | "
            f"мелких (< 2KB): {result.get('skipped_small', 0)}"
        )
        self.image_results.append_info(f"Директория: {out_path}")

        if out_path.exists():
            size = self._folder_size(out_path)
            self.image_results.append_info(f"Объём данных: {self._fmt_size(size)}")

        if result.get('failed'):
            self.image_results.append_warning(
                f"Не удалось загрузить: {len(result['failed'])} файл(а)"
            )
            for f in result['failed'][:5]:
                self.image_results.append_error(f"  {f}")

        archive = self._make_archive(out_path, domain, 'images')
        if archive:
            self.image_results.append_success(f"Архив создан: {Path(archive).name}")
        elif self.settings.get('auto_compress', False):
            self.image_results.append_warning("Архивация пропущена — нет скачанных файлов")
