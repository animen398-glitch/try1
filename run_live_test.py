#!/usr/bin/env python3
"""
Temporary live integration test for FrontendCloner.
Creates a sandboxed HTML page referencing real public CDN assets,
runs the full clone pipeline, and prints results + directory tree.

Usage:  python run_live_test.py
Remove: delete this file and live_test_input/ live_test_output/ when done.
"""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.frontend_cloner import FrontendCloner

# ── Directories ───────────────────────────────────────────────────────────────
INPUT_DIR  = Path('live_test_input')
OUTPUT_DIR = Path('live_test_output')

# ── Target URL & CDN assets (all public, no auth) ────────────────────────────
PAGE_URL = 'https://example.com/'

# Small, reliable CDN assets via jsDelivr (no redirects, no auth)
NORMALIZE_CSS = 'https://cdn.jsdelivr.net/npm/normalize.css@8.0.1/normalize.css'
ICON_SVG      = 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/icons/house.svg'
JQUERY_JS     = 'https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.slim.min.js'

DUMMY_HTML = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FrontendCloner — Live Test Page</title>
  <!-- External CSS (normalize.css ~1.5 KB) -->
  <link rel="stylesheet" href="{NORMALIZE_CSS}">
  <style>
    body {{ font-family: sans-serif; padding: 2rem; background: #f5f5f5; }}
    h1   {{ color: #333; }}
    .card {{ background:#fff; border-radius:8px; padding:1.5rem; display:inline-block; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>FrontendCloner Live Test</h1>
    <!-- External image (Bootstrap Icons SVG ~0.3 KB) -->
    <img src="{ICON_SVG}" alt="House icon" width="64" height="64">
    <p>This page references 3 external CDN assets.<br>
       FrontendCloner should download and localize all of them.</p>
  </div>
  <!-- External JS (jQuery slim ~23 KB) -->
  <script src="{JQUERY_JS}"></script>
  <script>
    // Inline script — should be preserved as-is
    document.addEventListener('DOMContentLoaded', function() {{
      console.log('page loaded offline');
    }});
  </script>
</body>
</html>
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def print_tree(base: Path, prefix: str = '') -> int:
    """Print directory tree; return total file count."""
    entries = sorted(base.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    count = 0
    for i, entry in enumerate(entries):
        is_last = i == len(entries) - 1
        connector = '\\-- ' if is_last else '+-- '
        if entry.is_file():
            size = entry.stat().st_size
            size_str = (f'{size} B' if size < 1024
                        else f'{size / 1024:.1f} KB' if size < 1024 ** 2
                        else f'{size / 1024 ** 2:.2f} MB')
            print(f'{prefix}{connector}{entry.name}  ({size_str})')
            count += 1
        else:
            print(f'{prefix}{connector}{entry.name}/')
            ext = '    ' if is_last else '|   '
            count += print_tree(entry, prefix + ext)
    return count


def total_size(path: Path) -> str:
    b = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
    if b < 1024:
        return f'{b} B'
    if b < 1024 ** 2:
        return f'{b / 1024:.1f} KB'
    return f'{b / 1024 ** 2:.2f} MB'


def sep(char: str = '-', width: int = 62):
    print(char * width)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # ── 1. Clean slate ───────────────────────────────────────────────────────
    for d in (INPUT_DIR, OUTPUT_DIR):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)

    sep('=')
    print('  FrontendCloner -- Live Integration Test')
    sep('=')
    print(f'  Input  : {INPUT_DIR.resolve()}')
    print(f'  Output : {OUTPUT_DIR.resolve()}')
    print(f'  Source : {PAGE_URL}')
    sep()
    print()

    # ── 2. Write dummy HTML ──────────────────────────────────────────────────
    html_file = INPUT_DIR / 'index.html'
    html_file.write_text(DUMMY_HTML, encoding='utf-8')

    site_map = [{'url': PAGE_URL, 'file': str(html_file.resolve())}]
    (INPUT_DIR / 'site_map.json').write_text(
        json.dumps(site_map, indent=2, ensure_ascii=False),
        encoding='utf-8',
    )

    print('[SETUP] Входные файлы:')
    print(f'  index.html   ({html_file.stat().st_size} B)')
    print(f'  site_map.json — url: "{PAGE_URL}"')
    print()
    print('[SETUP] Внешние ассеты для загрузки:')
    print(f'  CSS  : {NORMALIZE_CSS}')
    print(f'  IMG  : {ICON_SVG}')
    print(f'  JS   : {JQUERY_JS}')
    print()

    # ── 3. Configure & run FrontendCloner ────────────────────────────────────
    sep()
    print('[CLONE] Запуск FrontendCloner...')
    sep()

    log_lines = []

    def on_progress(msg: str):
        log_lines.append(msg)
        print(f'  {msg}')

    cloner = FrontendCloner()
    cloner.configure(
        str(INPUT_DIR),
        str(OUTPUT_DIR),
        profile='chrome_windows',
        rotate_ua=False,
    )
    cloner.set_progress_callback(on_progress)

    result = cloner.clone()

    sep()
    print()

    # ── 4. Result dict ───────────────────────────────────────────────────────
    print('[RESULT] Словарь результатов:')
    for key, val in result.items():
        if isinstance(val, list):
            if val:
                print(f'  {key}:')
                for item in val:
                    print(f'    - {item}')
            else:
                print(f'  {key}: []')
        else:
            print(f'  {key}: {val}')
    print()

    # ── 5. Directory tree ────────────────────────────────────────────────────
    sep()
    print(f'[TREE] Структура {OUTPUT_DIR}/:')
    sep()
    if OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        file_count = print_tree(OUTPUT_DIR)
        sep()
        print(f'  Файлов: {file_count}  |  Объём: {total_size(OUTPUT_DIR)}')
    else:
        print('  (выходная директория пуста)')
    print()

    # ── 6. Verify localisation ───────────────────────────────────────────────
    sep()
    print('[VERIFY] Проверка выходного HTML:')
    sep()

    out_html = OUTPUT_DIR / 'index.html'
    cdn_remaining = 0
    local_refs     = 0

    if out_html.exists():
        content = out_html.read_text(encoding='utf-8')
        cdn_remaining = sum(
            1 for url in (NORMALIZE_CSS, ICON_SVG, JQUERY_JS)
            if url in content
        )
        local_refs = content.count('assets/')
        inline_js  = 'page loaded offline' in content

        print(f'  CDN refs remaining in output HTML  : {cdn_remaining}  '
              f'{"[OK]" if cdn_remaining == 0 else "[!!]"}')
        print(f'  Local assets/ refs in output HTML  : {local_refs}  '
              f'{"[OK]" if local_refs > 0 else "[!!]"}')
        print(f'  Inline JS preserved                : {"[OK]" if inline_js else "[!!]"}')

        assets_dir = OUTPUT_DIR / 'assets'
        for subdir in ('css', 'img', 'js'):
            d = assets_dir / subdir
            if d.exists():
                files = list(d.iterdir())
                print(f'  assets/{subdir}/  — {len(files)} файл(а): '
                      f'{", ".join(f.name for f in files)}')
            else:
                print(f'  assets/{subdir}/  — не создана')
    else:
        print('  [!!]  Output index.html not found')

    print()
    sep('=')
    status = result.get('status', '')
    if status == 'Success' and cdn_remaining == 0 and local_refs > 0:
        print('  [OK]  TEST PASSED -- page fully localised')
    elif status == 'Success':
        print('  [~~]  TEST PARTIAL -- some assets not downloaded')
        print('        (check network / CDN availability)')
    else:
        print(f'  [!!]  TEST FAILED -- status: {status}')
    sep('=')
    print()


if __name__ == '__main__':
    main()
