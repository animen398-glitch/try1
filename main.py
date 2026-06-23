import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Pin the qtpy binding before any Qt import (variant-B: PySide6). setdefault so
# an external QT_API still wins (e.g. QT_API=pyqt5 to fall back to the old binding).
os.environ.setdefault("QT_API", "pyside6")

# Establish the process-wide PathManager up front, before anything imports
# core.config, so a frozen .exe resolves its writable data dir (%APPDATA%)
# rather than the ephemeral PyInstaller _MEIPASS extraction dir.
from core.paths import init_path_manager

init_path_manager()

from qtpy.QtWidgets import QApplication
from gui.main_window import MainWindow


def main() -> int:
    # Packaging smoke check: build the window headless and exit 0 without ever
    # entering the event loop or showing a window. Run against the *frozen* .exe
    # in CI to catch PyInstaller regressions (a dropped hidden import or bundled
    # data file) that source-level tests can't see — those only surface when the
    # real import graph runs from inside the .exe.
    self_check = "--self-check" in sys.argv
    if self_check:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    app = QApplication(sys.argv)
    app.setApplicationName("Advanced Site Analyzer")
    app.setOrganizationName("SiteAnalyzer")

    # Visual theme (F6) — opt-in; 'system' (default) keeps the current look.
    from core.config import load_settings
    from gui.theme import apply_theme
    apply_theme(app, load_settings().get('gui_theme', 'system'))

    window = MainWindow()

    if self_check:
        tabs = getattr(window, "tabs", None)
        n = tabs.count() if tabs is not None else 0
        print(f"self-check OK — {n} tab(s)")
        return 0

    # First-run onboarding + system-health screen (one-time; reachable later from
    # the navigation footer). Skipped in --self-check (no dialogs in CI smoke).
    from gui.first_run import maybe_show_first_run
    maybe_show_first_run(window)

    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
