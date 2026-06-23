import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, Optional, Union

from utils.operation_registry import OperationRegistry
from utils.subprocess_utils import run_hidden

# Operation history shares the orchestrator's database so downloads appear in
# the GUI "История операций" tab alongside the other pipeline phases.
from core.config import OPERATIONS_DB
DEFAULT_DB = str(OPERATIONS_DB)

# Quality preset -> yt-dlp --format expression.
# The "<=" presets cap resolution and merge the best video+audio streams,
# which needs ffmpeg; _progressive_fallback() is used when ffmpeg is absent.
QUALITY_FORMATS: Dict[str, str] = {
    '4k':    'bv*[height<=2160]+ba/b[height<=2160]',
    '1440p': 'bv*[height<=1440]+ba/b[height<=1440]',
    '1080p': 'bv*[height<=1080]+ba/b[height<=1080]',
    '720p':  'bv*[height<=720]+ba/b[height<=720]',
    'best':  'bv*+ba/b',
    'audio': 'ba/b',
}

# When ffmpeg is missing we cannot merge separate streams, so fall back to a
# single progressive stream capped at the same height.
_PROGRESSIVE_FALLBACK: Dict[str, str] = {
    '4k':    'b[height<=2160]',
    '1440p': 'b[height<=1440]',
    '1080p': 'b[height<=1080]',
    '720p':  'b[height<=720]',
    'best':  'b',
    'audio': 'ba/b',
}


class VideoDownloader:
    """Загрузчик видео через yt-dlp с записью операций в OperationRegistry.

    Поддерживает выбор качества (вплоть до 4K через yt-dlp + ffmpeg merge) и
    сессионные cookies для авторизованного скачивания закрытого контента.
    """

    def __init__(self, registry: Optional[OperationRegistry] = None,
                 data_registry=None,
                 quality: str = 'best', timeout: int = 300,
                 cookies: Optional[str] = None,
                 cookies_from_browser: Optional[str] = None):
        self.registry = registry or OperationRegistry(db_path=DEFAULT_DB)
        self._data_registry = data_registry
        # Accept a raw yt-dlp format string too, but prefer named presets.
        self.quality = quality
        self.timeout = timeout
        self.cookies = cookies                      # path to a Netscape cookies.txt
        self.cookies_from_browser = cookies_from_browser  # e.g. 'chrome', 'firefox'
        self.progress_callback: Optional[Callable] = None

    def set_progress_callback(self, cb: Callable) -> None:
        self.progress_callback = cb

    @staticmethod
    def is_available() -> bool:
        return shutil.which('yt-dlp') is not None

    @staticmethod
    def has_ffmpeg() -> bool:
        return shutil.which('ffmpeg') is not None

    def _log(self, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(msg)

    def _record_data(self, source: str, data_type: str, content: str,
                     metadata: Optional[Dict] = None) -> None:
        """Сохранить найденный контент в DataRegistry (не ломая основную операцию)."""
        try:
            if self._data_registry is None:
                from core.registry import DataRegistry
                self._data_registry = DataRegistry()
            self._data_registry.add_record(source, data_type, content, metadata)
        except Exception as e:
            self._log(f'Не удалось записать в DataRegistry: {e}')

    def _resolve_format(self) -> str:
        """Pick the yt-dlp format string for the configured quality.

        Named presets that require stream merging degrade to a progressive
        stream when ffmpeg is unavailable; unknown values pass through as a
        raw yt-dlp format expression.
        """
        preset = self.quality.lower()
        if preset not in QUALITY_FORMATS:
            return self.quality  # raw format expression
        if preset != 'audio' and not self.has_ffmpeg():
            self._log('ffmpeg не найден — качество ограничено прогрессивным потоком '
                      '(установите ffmpeg для 4K/1080p с раздельными дорожками)')
            return _PROGRESSIVE_FALLBACK[preset]
        return QUALITY_FORMATS[preset]

    def _build_cmd(self, url: str, output_template: str) -> list:
        fmt = self._resolve_format()
        cmd = [
            'yt-dlp',
            '--format', fmt,
            '--output', output_template,
            '--no-playlist',
        ]
        # Merge separate video+audio into a single mp4 when ffmpeg is present.
        if '+' in fmt and self.has_ffmpeg():
            cmd += ['--merge-output-format', 'mp4']
        if self.quality.lower() == 'audio':
            cmd += ['--extract-audio', '--audio-format', 'mp3']
        # Authorized downloads via session cookies.
        if self.cookies:
            cmd += ['--cookies', str(self.cookies)]
        elif self.cookies_from_browser:
            cmd += ['--cookies-from-browser', self.cookies_from_browser]
        cmd.append(url)
        return cmd

    def download_video(self, url: str, output_dir: Union[str, Path]) -> Dict:
        """Скачать видео в output_dir; начало/итог операции пишутся в реестр."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        result = {'url': url, 'status': 'Not started', 'file': None,
                  'quality': self.quality}
        op_id = self.registry.start(
            target=url, phase='video_download', output_dir=str(out_path),
            metadata={'quality': self.quality, 'ffmpeg': self.has_ffmpeg()},
        )

        if not self.is_available():
            msg = 'yt-dlp not found. Install: pip install yt-dlp'
            result['status'] = f'Error: {msg}'
            self.registry.finish(op_id, status='failed', error=msg)
            return result

        output_template = str(out_path / '%(title)s.%(ext)s')
        cmd = self._build_cmd(url, output_template)

        try:
            self._log(f'Загружаю [{self.quality}]: {url}')
            process = run_hidden(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )

            if process.returncode == 0:
                result['status'] = 'Success'
                result['output'] = process.stdout
                self.registry.finish(op_id, status='success')
                self._record_data(
                    source=url, data_type='video', content=str(out_path),
                    metadata={'quality': self.quality},
                )
            else:
                error = (process.stderr or 'unknown error')[:500]
                result['status'] = f'Error: {error}'
                self.registry.finish(op_id, status='failed', error=error)

        except subprocess.TimeoutExpired:
            error = f'timeout ({self.timeout}s)'
            result['status'] = f'Error: {error}'
            self.registry.finish(op_id, status='failed', error=error)
        except Exception as e:
            result['status'] = f'Error: {e}'
            self.registry.finish(op_id, status='failed', error=str(e))

        return result
