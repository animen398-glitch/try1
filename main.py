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


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Advanced Site Analyzer")
    app.setOrganizationName("SiteAnalyzer")
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
