import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Establish the process-wide PathManager up front, before anything imports
# core.config, so a frozen .exe resolves its writable data dir (%APPDATA%)
# rather than the ephemeral PyInstaller _MEIPASS extraction dir.
from core.paths import init_path_manager

init_path_manager()

from PyQt5.QtWidgets import QApplication
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
    app.setStyle("Fusion")

    window = MainWindow()

    if self_check:
        tabs = getattr(window, "tabs", None)
        n = tabs.count() if tabs is not None else 0
        print(f"self-check OK — {n} tab(s)")
        return 0

    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
