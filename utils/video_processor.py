import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, Optional, Union

from utils.operation_registry import OperationRegistry

# Operation history shares the orchestrator's database so downloads appear in
# the GUI "История операций" tab alongside the other pipeline phases.
DEFAULT_DB = 'data/operations.db'


class VideoDownloader:
    """Загрузчик видео через yt-dlp с записью операций в OperationRegistry."""

    def __init__(self, registry: Optional[OperationRegistry] = None,
                 quality: str = 'best', timeout: int = 300):
        self.registry = registry or OperationRegistry(db_path=DEFAULT_DB)
        self.quality = quality
        self.timeout = timeout
        self.progress_callback: Optional[Callable] = None

    def set_progress_callback(self, cb: Callable) -> None:
        self.progress_callback = cb

    @staticmethod
    def is_available() -> bool:
        return shutil.which('yt-dlp') is not None

    def _log(self, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(msg)

    def download_video(self, url: str, output_dir: Union[str, Path]) -> Dict:
        """Скачать видео в output_dir; начало/итог операции пишутся в реестр."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        result = {'url': url, 'status': 'Not started', 'file': None}
        op_id = self.registry.start(
            target=url, phase='video_download', output_dir=str(out_path),
            metadata={'quality': self.quality},
        )

        if not self.is_available():
            msg = 'yt-dlp not found. Install: pip install yt-dlp'
            result['status'] = f'Error: {msg}'
            self.registry.finish(op_id, status='failed', error=msg)
            return result

        output_template = str(out_path / '%(title)s.%(ext)s')
        cmd = [
            'yt-dlp',
            '--format', self.quality,
            '--output', output_template,
            '--no-playlist',
            url,
        ]

        try:
            self._log(f'Загружаю: {url}')
            process = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout,
            )

            if process.returncode == 0:
                result['status'] = 'Success'
                result['output'] = process.stdout
                self.registry.finish(op_id, status='success')
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
