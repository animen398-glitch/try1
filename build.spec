# build.spec — PyInstaller, onefile, без консоли (PySide6 GUI via qtpy seam)
# Сборка:  pyinstaller build.spec --clean --noconfirm
# Результат: dist/SiteAnalyzer.exe

import os

from PyInstaller.utils.hooks import collect_all

# qfluentwidgets (variant B Fluent navigation) ships its own qss / fonts / SVG
# icons as package data — bundle them or the frozen GUI can't theme/render.
_fluent_datas, _fluent_bins, _fluent_hidden = collect_all('qfluentwidgets')

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=_fluent_bins,
    datas=[
        ('configs', 'configs'),   # settings.json, targets.json (значения по умолчанию)
        # External tab/analyzer plugins are discovered at runtime from
        # resource_root/plugins (== _MEIPASS/plugins when frozen). Bundle the dir
        # or the frozen .exe loses them (e.g. the Scrapy tab) — see PluginManager.
        ('plugins', 'plugins'),
    ] + _fluent_datas,
    hiddenimports=[
        'requests',
        'bs4',
        # External plugins are loaded as DATA files at runtime, so PyInstaller's
        # static analysis never sees their imports. The Scrapy tab plugin imports
        # core.scrapy_crawler (reachable from nowhere else in the graph) — declare
        # it here or the tab silently drops in the frozen build. scrapy itself is
        # intentionally NOT bundled (heavy/optional); the crawl runs in a child
        # process and the tab explains how to enable it.
        'core.scrapy_crawler',
    ] + _fluent_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Тяжёлые опциональные модули — НЕ нужны для GUI и раздувают .exe.
        # Уберите из excludes, если используете эти функции:
        'playwright',     # динамический анализ (отдельно ставит chromium)
        'fastapi',        # веб-консоль (main_orchestrator --web)
        'uvicorn',
        # PyQt5 — больше не активный байндинг (GUI на PySide6 через qtpy);
        # исключаем, чтобы не тянуть второй Qt в .exe, если он установлен.
        'PyQt5',
        # Неиспользуемые модули Qt6 Addons — приложению не нужны и сильно
        # раздувают .exe (замер P0: их исключение даёт ~51 MB вместо ~61 MB).
        'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets',
        'PySide6.QtWebEngineQuick', 'PySide6.QtQuick', 'PySide6.QtQuick3D',
        'PySide6.QtQml', 'PySide6.QtQmlModels',
        'PySide6.Qt3DCore', 'PySide6.Qt3DRender', 'PySide6.Qt3DInput',
        'PySide6.Qt3DExtras', 'PySide6.Qt3DAnimation', 'PySide6.Qt3DLogic',
        'PySide6.QtCharts', 'PySide6.QtDataVisualization', 'PySide6.QtGraphs',
        'PySide6.QtMultimedia', 'PySide6.QtMultimediaWidgets',
        'PySide6.QtSpatialAudio', 'PySide6.QtPdf', 'PySide6.QtPdfWidgets',
        'PySide6.QtLocation', 'PySide6.QtPositioning', 'PySide6.QtBluetooth',
        'PySide6.QtNfc', 'PySide6.QtSensors', 'PySide6.QtSerialPort',
        'PySide6.QtSerialBus', 'PySide6.QtWebSockets', 'PySide6.QtWebChannel',
        'PySide6.QtRemoteObjects', 'PySide6.QtScxml', 'PySide6.QtStateMachine',
        'PySide6.QtSql', 'PySide6.QtTest', 'PySide6.QtDesigner',
        'PySide6.QtUiTools', 'PySide6.QtHelp', 'PySide6.QtHttpServer',
        'PySide6.QtNetworkAuth', 'PySide6.QtTextToSpeech',
    ],
    noarchive=False,
)

# Variant-B size trim: the PySide6 PyInstaller hook force-collects Qt6 plugins,
# translations and several DLLs that a widgets-only GUI never uses — and plain
# `excludes` (module-level) don't drop them. So filter the collected TOCs here.
# OpenGL/d3dcompiler are deliberately KEPT (software-render fallback safety).
_DROP_DLL = ('qt6quick', 'qt6qml', 'qt6pdf', 'qt6virtualkeyboard')
_DROP_PLUGIN_DIRS = ('qmltooling', 'qmllint', 'virtualkeyboard', 'designer',
                     'pdf', 'sqldrivers', 'webview', 'multimedia', 'position',
                     'sensors', 'texttospeech', 'renderplugins', 'assetimporters')


def _keep(dest):
    d = dest.replace('\\', '/').lower()
    if '/translations/' in d and d.endswith('.qm'):
        return False                       # Qt's own UI strings (app ships RU)
    if any(k in os.path.basename(d) for k in _DROP_DLL):
        return False
    if any(f'/{p}/' in d for p in _DROP_PLUGIN_DIRS):
        return False
    return True


a.binaries = [b for b in a.binaries if _keep(b[0])]
a.datas = [d for d in a.datas if _keep(d[0])]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SiteAnalyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,              # <-- без чёрного окна CMD (--noconsole)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/app.ico',     # <-- положите сюда свою иконку (.ico)
)
