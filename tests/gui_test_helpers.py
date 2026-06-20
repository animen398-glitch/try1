"""Lightweight QWidget hosts for tab-mixin tests.

The real MainWindow is a qfluentwidgets FluentWindow. On Windows/PySide6 in the
offscreen test platform, repeatedly constructing that native shell can crash the
Python process during teardown. These hosts keep tab unit tests focused on the
mixins they exercise while avoiding the full app chrome.
"""

from qtpy.QtWidgets import QLabel, QProgressBar, QWidget

from gui.tab_accuracy import AccuracyTabMixin
from gui.tab_assets import AssetsTabMixin
from gui.tab_dashboard import DashboardTabMixin
from gui.tab_findings import FindingsTabMixin
from gui.tab_technology_risk import TechnologyRiskTabMixin


class _Status:
    def __init__(self):
        self.message = ""

    def showMessage(self, text: str, timeout: int = 0):
        self.message = text


class _BaseHost(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = {}
        self.status_bar = _Status()
        self.progress_bar = QProgressBar()
        self.task_indicator = QLabel("")

    def _set_busy(self, busy: bool):
        self.progress_bar.setVisible(busy)

    def _run_async(self, *args, **kwargs):
        return None


class DashboardHost(_BaseHost, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._dashboard_loading = False
        self._dashboard_table_loading = False
        self._dashboard_filter_pending = False
        self._dashboard_loaded = False
        self._endpoint_filter = None
        self._build_dashboard_tab()


class AssetsHost(_BaseHost, AssetsTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._assets_loading = False
        self._assets_loaded = False
        self._assets_table_loading = False
        self._assets_filter_pending = False
        self._build_assets_tab()


class FindingsHost(_BaseHost, FindingsTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._findings_loading = False
        self._findings_loaded = False
        self._findings_table_loading = False
        self._findings_filter_pending = False
        self._build_findings_tab()


class AccuracyHost(_BaseHost, AccuracyTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._acc_loading = False
        self._acc_loaded = False
        self._acc_table_loading = False
        self._acc_filter_pending = False
        self._build_accuracy_tab()


class TechnologyRiskHost(_BaseHost, TechnologyRiskTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._tr_loading = False
        self._tr_loaded = False
        self._tr_table_loading = False
        self._tr_filter_pending = False
        self._build_technology_risk_tab()
