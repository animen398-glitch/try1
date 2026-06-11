from PyQt5.QtWidgets import QMainWindow

from core import config
from gui.task_runner import TaskRunnerMixin
from gui.window_chrome import WindowChromeMixin
from gui.window_helpers import WindowHelpersMixin
from gui.tab_system import SystemTabMixin
from gui.tab_api import ApiTabMixin
from gui.tab_capture import CaptureTabMixin
from gui.tab_design import DesignTabMixin
from gui.tab_media import ImageTabMixin, VideoTabMixin
from gui.tab_recon import ReconTabMixin
from gui.tab_subdomain import SubdomainTabMixin
from gui.tab_clone import CloneTabMixin
from gui.tab_collection import FinalReportTabMixin
from gui.tab_cookie import CookieAuditTabMixin
from gui.tab_dashboard import DashboardTabMixin
from gui.tab_history import HistoryTabMixin
from utils.task_manager import TaskManager


class MainWindow(QMainWindow, TaskRunnerMixin, WindowChromeMixin,
                 WindowHelpersMixin, SystemTabMixin, ApiTabMixin,
                 VideoTabMixin, ImageTabMixin, CaptureTabMixin,
                 DesignTabMixin, ReconTabMixin, SubdomainTabMixin,
                 CloneTabMixin, CookieAuditTabMixin, FinalReportTabMixin,
                 DashboardTabMixin, HistoryTabMixin):
    """Основное окно Advanced Site Analyzer.

    Тонкий контейнер: инициализирует состояние и собирает окно из mixin'ов —
    раннер задач (gui/task_runner.py), оконный chrome (gui/window_chrome.py),
    общие helpers (gui/window_helpers.py) и per-tab модули (gui/tab_*.py). Вся
    логика живёт в этих mixin'ах; здесь остаются только __init__ и closeEvent
    (Qt-override, делегирующий слив рабочих потоков в раннер задач).
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Site Analyzer")
        self.setMinimumSize(900, 650)
        # Process-default PathManager (frozen-build aware); plugins/tabs reach
        # it via window.paths for workspace/temp/db locations.
        self.paths = config.get_path_manager()
        self.settings = config.load_settings()
        # Single source of truth for every running background task.
        # Maps task_id -> _TaskHandle; entries are added in _start_task and
        # removed only after the OS thread has fully exited. All concurrency
        # safety (no GC of a live QThread) flows through this one dict.
        self._tasks: dict = {}
        self._next_task_id: int = 0
        self._last_recon_combined: dict = {}
        self._active_subdomain_scanner = None
        self._subdomain_rows: dict = {}
        self._active_capturer = None
        self._active_cloner = None
        self._active_collector = None
        self._history_rows: list = []
        self._history_loading = False
        self._history_view_cleared = False
        self._dashboard_loading = False
        self._dashboard_table_loading = False
        self._dashboard_filter_pending = False
        self._dashboard_loaded = False
        self._endpoint_filter = None  # active endpoint occurrence filter (or None)
        self.task_manager = TaskManager()

        # Build the window from the mixins (chrome lives in WindowChromeMixin).
        self._build_menu()
        self._build_central()
        self._build_statusbar()
        self._check_dependencies()
        self._report_plugin_errors()

    def closeEvent(self, event):
        # Drain in-flight worker threads (TaskRunnerMixin) so none is destroyed
        # mid-run, then let Qt close the window.
        self._await_running_tasks()
        super().closeEvent(event)
