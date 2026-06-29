from core import config
from gui.fluent_nav import FluentWindowBase
from gui.task_runner import TaskRunnerMixin
from gui.monitor_runner import MonitorRunnerMixin
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
from gui.tab_security import SecurityAuditTabMixin
from gui.tab_findings import FindingsTabMixin
from gui.tab_remediation import RemediationTabMixin
from gui.tab_assets import AssetsTabMixin
from gui.tab_intelligence import IntelligenceTabMixin
from gui.tab_criticality import CriticalityTabMixin
from gui.tab_exposure import ExposureTabMixin
from gui.tab_attack_paths import AttackPathsTabMixin
from gui.tab_accuracy import AccuracyTabMixin
from gui.tab_technology_risk import TechnologyRiskTabMixin
from gui.tab_osint_catalog import OsintCatalogTabMixin
from gui.tab_iac import IacTabMixin
from gui.tab_audit_runs import AuditRunsTabMixin
from gui.tab_missions import MissionsTabMixin
from gui.tab_timeline import TimelineTabMixin
from gui.tab_overview import OverviewTabMixin
from gui.tab_dashboard import DashboardTabMixin
from gui.tab_history import HistoryTabMixin
from utils.task_manager import TaskManager


class MainWindow(FluentWindowBase, TaskRunnerMixin, MonitorRunnerMixin,
                 WindowChromeMixin,
                 WindowHelpersMixin, SystemTabMixin, ApiTabMixin,
                 VideoTabMixin, ImageTabMixin, CaptureTabMixin,
                 DesignTabMixin, ReconTabMixin, SubdomainTabMixin,
                 CloneTabMixin, CookieAuditTabMixin, SecurityAuditTabMixin,
                 FinalReportTabMixin, FindingsTabMixin, RemediationTabMixin,
                 AssetsTabMixin,
                 IntelligenceTabMixin, CriticalityTabMixin, ExposureTabMixin,
                 AttackPathsTabMixin,
                 AccuracyTabMixin, TechnologyRiskTabMixin, OsintCatalogTabMixin,
                 IacTabMixin, AuditRunsTabMixin, MissionsTabMixin,
                 TimelineTabMixin,
                 OverviewTabMixin, DashboardTabMixin, HistoryTabMixin):
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
        self._findings_loading = False
        self._findings_loaded = False
        self._findings_table_loading = False
        self._findings_filter_pending = False
        self._rem_loading = False
        self._rem_loaded = False
        self._rem_table_loading = False
        self._rem_filter_pending = False
        self._assets_loading = False
        self._assets_loaded = False
        self._assets_table_loading = False
        self._assets_filter_pending = False
        self._intel_loading = False
        self._intel_loaded = False
        self._intel_table_loading = False
        self._intel_filter_pending = False
        self._crit_loading = False
        self._crit_loaded = False
        self._crit_table_loading = False
        self._crit_filter_pending = False
        self._crit_business = {}
        self._crit_reselect_fp = None
        self._exp_loading = False
        self._exp_loaded = False
        self._exp_table_loading = False
        self._exp_filter_pending = False
        self._path_loading = False
        self._attack_paths_loaded = False
        self._path_table_loading = False
        self._path_filter_pending = False
        self._acc_loading = False
        self._acc_loaded = False
        self._acc_table_loading = False
        self._acc_filter_pending = False
        self._tr_loading = False
        self._tr_loaded = False
        self._tr_table_loading = False
        self._tr_filter_pending = False
        self._osint_loading = False
        self._osint_loaded = False
        self._osint_table_loading = False
        self._osint_filter_pending = False
        self._audit_loading = False
        self._audit_running = False
        self._timeline_loading = False
        self._timeline_loaded = False
        self._timeline_data_loading = False
        self._timeline_pending = False
        self._overview_loading = False
        self._overview_loaded = False
        self._overview_series_loading = False
        self._overview_series_pending = False
        self._overview_graph_loading = False
        self._overview_companies_loading = False
        self._overview_assign_loading = False
        self.task_manager = TaskManager()

        # Build the window from the mixins (chrome lives in WindowChromeMixin).
        # Order matters under FluentWindow: the status bar is created first, then
        # _build_central mounts it beneath the nav+content row; menu actions are
        # added to the navigation footer.
        self._build_statusbar()
        self._build_central()
        self._build_menu()
        self._check_dependencies()
        self._report_plugin_errors()
        # In-app Continuous Monitoring (F3) — opt-in background watcher; needs
        # the status bar (indicator) and tabs (Collection label) already built.
        self._init_monitor_runner()

    def closeEvent(self, event):
        # Stop the background monitor, then drain in-flight worker threads
        # (TaskRunnerMixin) so none is destroyed mid-run, then let Qt close.
        self._stop_monitor_scheduler()
        self._await_running_tasks()
        super().closeEvent(event)

    def eventFilter(self, obj, event):
        handled = self._window_chrome_event_filter(obj, event)
        if handled is not None:
            return handled
        return super().eventFilter(obj, event)
