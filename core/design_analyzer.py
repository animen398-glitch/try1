import json
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set


class DesignAnalyzer:
    """
    Scans captured HTML/CSS files to extract color palette and typography,
    writing results to ui_palette.json for the Design Lab GUI tab.
    """

    _HEX_RE = re.compile(
        r'(?<![&\w])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b'
    )
    _RGB_RE = re.compile(
        r'rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})(?:\s*,\s*[\d.]+)?\s*\)',
        re.IGNORECASE,
    )
    _HSL_RE = re.compile(
        r'hsla?\(\s*[\d.]+\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?(?:\s*,\s*[\d.]+)?\s*\)',
        re.IGNORECASE,
    )
    _FONT_FAMILY_RE = re.compile(r'font-family\s*:\s*([^;}{]+)', re.IGNORECASE)
    _FONT_FACE_NAME_RE = re.compile(
        r'@font-face\s*\{[^}]*?font-family\s*:\s*([^;]+)',
        re.IGNORECASE | re.DOTALL,
    )
    _STYLE_BLOCK_RE = re.compile(r'<style[^>]*>(.*?)</style>', re.IGNORECASE | re.DOTALL)

    _GENERIC_FONTS = frozenset({
        'serif', 'sans-serif', 'monospace', 'cursive', 'fantasy',
        'system-ui', 'ui-serif', 'ui-sans-serif', 'ui-monospace',
        'inherit', 'initial', 'unset', 'revert',
    })

    def __init__(self):
        self.source_dir: Optional[Path] = None
        self.output_file: Optional[Path] = None
        self.progress_callback: Optional[Callable] = None

    def configure(self, source_dir: str, output_file: Optional[str] = None):
        self.source_dir = Path(source_dir)
        self.output_file = (
            Path(output_file) if output_file
            else self.source_dir / 'ui_palette.json'
        )

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def _gather_css(self):
        chunks: List[str] = []
        css_files = list(self.source_dir.rglob('*.css'))
        html_files = list(self.source_dir.rglob('*.html'))

        for f in css_files:
            try:
                chunks.append(f.read_text(encoding='utf-8', errors='ignore'))
                self._log(f"CSS: {f.name}")
            except Exception:
                pass

        for f in html_files:
            try:
                html = f.read_text(encoding='utf-8', errors='ignore')
                for block in self._STYLE_BLOCK_RE.findall(html):
                    chunks.append(block)
            except Exception:
                pass

        return '\n'.join(chunks), len(css_files), len(html_files)

    def _expand_hex(self, raw: str) -> str:
        h = raw.lstrip('#')
        if len(h) in (3, 4):
            h = ''.join(c * 2 for c in h)
        return f'#{h.upper()}'

    def _extract_colors(self, css: str) -> List[Dict]:
        colors: List[Dict] = []
        seen: Set[str] = set()

        for m in self._HEX_RE.finditer(css):
            key = self._expand_hex(m.group())
            if key not in seen:
                seen.add(key)
                colors.append({'type': 'hex', 'value': key, 'raw': m.group()})

        for m in self._RGB_RE.finditer(css):
            r, g, b = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if all(0 <= x <= 255 for x in (r, g, b)):
                key = f'#{r:02X}{g:02X}{b:02X}'
                if key not in seen:
                    seen.add(key)
                    colors.append({'type': 'rgb', 'value': m.group().strip(), 'hex': key})

        for m in self._HSL_RE.finditer(css):
            val = m.group().strip()
            if val not in seen:
                seen.add(val)
                colors.append({'type': 'hsl', 'value': val})

        return colors

    def _clean_name(self, raw: str) -> str:
        return raw.strip().strip('"\'').split(',')[0].strip().strip('"\'').strip()

    def _extract_fonts(self, css: str) -> List[str]:
        fonts: Set[str] = set()

        for m in self._FONT_FAMILY_RE.finditer(css):
            for part in m.group(1).split(','):
                name = self._clean_name(part)
                if name and name.lower() not in self._GENERIC_FONTS:
                    fonts.add(name)

        for m in self._FONT_FACE_NAME_RE.finditer(css):
            name = self._clean_name(m.group(1))
            if name and name.lower() not in self._GENERIC_FONTS:
                fonts.add(name)

        return sorted(fonts)

    def analyze(self) -> Dict:
        result: Dict = {
            'source_dir': str(self.source_dir),
            'output_file': str(self.output_file),
            'colors': [],
            'fonts': [],
            'stats': {'css_files': 0, 'html_files': 0, 'total_colors': 0, 'total_fonts': 0},
            'status': 'Not started',
        }

        if not self.source_dir or not self.source_dir.exists():
            result['status'] = 'Error: source directory not found'
            return result

        css_text, n_css, n_html = self._gather_css()
        result['stats']['css_files'] = n_css
        result['stats']['html_files'] = n_html
        self._log(f"Источников: {n_css} CSS, {n_html} HTML")

        if not css_text.strip():
            result['status'] = 'Warning: no CSS content found'
            self._save(result)
            return result

        self._log("Анализирую цвета...")
        result['colors'] = self._extract_colors(css_text)

        self._log("Анализирую шрифты...")
        result['fonts'] = self._extract_fonts(css_text)

        result['stats']['total_colors'] = len(result['colors'])
        result['stats']['total_fonts'] = len(result['fonts'])
        result['status'] = 'Success'
        self._log(
            f"Готово: {result['stats']['total_colors']} цветов, "
            f"{result['stats']['total_fonts']} шрифтов"
        )
        self._save(result)
        return result

    def _save(self, data: Dict):
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self.output_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding='utf-8',
            )
        except Exception:
            pass
