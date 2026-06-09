import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union


class FileCompressor:
    """Архивация результатов в ZIP (и RAR при наличии winrar/rar в PATH)"""

    @staticmethod
    def to_zip(source: Union[str, Path], output_path: Optional[str] = None) -> str:
        source = Path(source)
        if output_path is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = str(source.parent / f"{source.name}_{ts}.zip")

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            if source.is_dir():
                for file in source.rglob('*'):
                    if file.is_file():
                        zf.write(file, file.relative_to(source.parent))
            else:
                zf.write(source, source.name)

        return output_path

    @staticmethod
    def files_to_zip(files: List[str], output_path: str) -> str:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filepath in files:
                p = Path(filepath)
                if p.exists():
                    zf.write(p, p.name)
        return output_path

    @staticmethod
    def get_zip_info(zip_path: str) -> Dict:
        result = {'files': [], 'total_size': 0, 'compressed_size': 0}
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for info in zf.infolist():
                    result['files'].append(info.filename)
                    result['total_size'] += info.file_size
                    result['compressed_size'] += info.compress_size
        except Exception as e:
            result['error'] = str(e)
        return result

    @staticmethod
    def to_rar(source: Union[str, Path], output_path: Optional[str] = None) -> str:
        """RAR через системный rar/winrar; при отсутствии — fallback на ZIP"""
        source = Path(source)
        if output_path is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = str(source.parent / f"{source.name}_{ts}.rar")

        rar_exe = shutil.which('rar') or shutil.which('winrar')
        if not rar_exe:
            return FileCompressor.to_zip(source, output_path.replace('.rar', '.zip'))

        cmd = [rar_exe, 'a', '-r', output_path, str(source)]
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
        if proc.returncode != 0:
            return FileCompressor.to_zip(source, output_path.replace('.rar', '.zip'))

        return output_path
