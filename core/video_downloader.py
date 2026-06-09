import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, Optional


class VideoDownloader:
    """Загрузчик видео через yt-dlp"""

    def __init__(self):
        self.output_dir: Optional[Path] = None
        self.quality: str = 'best'
        self.progress_callback: Optional[Callable] = None

    def configure(self, output_dir: str, quality: str = 'best'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.quality = quality

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    @staticmethod
    def is_available() -> bool:
        return shutil.which('yt-dlp') is not None

    def download(self, url: str) -> Dict:
        result = {'url': url, 'status': 'Not started', 'file': None}

        if not self.output_dir:
            result['status'] = 'Error: output directory not set'
            return result

        if not self.is_available():
            result['status'] = 'Error: yt-dlp not found. Install: pip install yt-dlp'
            return result

        output_template = str(self.output_dir / '%(title)s.%(ext)s')
        cmd = [
            'yt-dlp',
            '--format', self.quality,
            '--output', output_template,
            '--no-playlist',
            url
        ]

        try:
            if self.progress_callback:
                self.progress_callback(f"Загружаю: {url}")

            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if process.returncode == 0:
                result['status'] = 'Success'
                result['output'] = process.stdout
            else:
                result['status'] = f'Error: {process.stderr[:500]}'

        except subprocess.TimeoutExpired:
            result['status'] = 'Error: timeout (300s)'
        except Exception as e:
            result['status'] = f'Error: {str(e)}'

        return result
