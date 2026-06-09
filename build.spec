# build.spec — PyInstaller, onefile, без консоли (PyQt5 GUI)
# Сборка:  pyinstaller build.spec --clean --noconfirm
# Результат: dist/SiteAnalyzer.exe

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('configs', 'configs'),   # settings.json, targets.json (значения по умолчанию)
    ],
    hiddenimports=[
        'requests',
        'bs4',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Тяжёлые опциональные модули — НЕ нужны для GUI и раздувают .exe.
        # Уберите из excludes, если используете эти функции:
        'playwright',     # динамический анализ (отдельно ставит chromium)
        'fastapi',        # веб-консоль (main_orchestrator --web)
        'uvicorn',
    ],
    noarchive=False,
)

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
