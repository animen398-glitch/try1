"""Lightweight QWidget hosts for tab-mixin tests.

The real MainWindow is a qfluentwidgets FluentWindow. On Windows/PySide6 in the
offscreen test platform, repeatedly constructing that native shell can crash the
Python process during teardown. These hosts keep tab unit tests focused on the
mixins they exercise while avoiding the full app chrome.
"""

from qtpy.QtWidgets import QLabel, QProgressBar, QWidget

from gui.tab_accuracy import AccuracyTabMixin
from gui.tab_assets import AssetsTabMixin
from gui.tab_criticality import CriticalityTabMixin
from gui.tab_dashboard import DashboardTabMixin
from gui.tab_findings import FindingsTabMixin
from gui.tab_iac import IacTabMixin
from gui.tab_osint_catalog import OsintCatalogTabMixin
from gui.tab_overview import OverviewTabMixin
from gui.tab_technology_risk import TechnologyRiskTabMixin
from gui.tab_timeline import TimelineTabMixin
from gui.tab_audit_runs import AuditRunsTabMixin
from gui.tab_missions import MissionsTabMixin
from gui.tab_engagement import EngagementsTabMixin


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


class _SyncRunMixin:
    """e2e: run ``_run_async`` **inline** (no QThread) so a ``QTest`` click drives
    the full handler → worker → callback → UI chain deterministically.

    Mirrors the real ``TaskRunnerMixin`` contract ``_run_async(work, on_done)``
    but synchronously, so headless GUI e2e tests stay thread-free and
    deterministic. Override beats ``_BaseHost._run_async`` via MRO."""

    def _run_async(self, work, on_done=None, *args, **kwargs):
        result = work()
        if on_done is not None:
            on_done(result)
        return result


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


class CriticalityHost(_BaseHost, CriticalityTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._crit_loading = False
        self._crit_loaded = False
        self._crit_table_loading = False
        self._crit_filter_pending = False
        self._crit_reselect_fp = None
        self._build_criticality_tab()


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


class TimelineHost(_BaseHost, TimelineTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._timeline_loading = False
        self._timeline_loaded = False
        self._timeline_data_loading = False
        self._timeline_pending = False
        self._build_timeline_tab()


class OsintCatalogHost(_BaseHost, OsintCatalogTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._osint_loading = False
        self._osint_loaded = False
        self._osint_table_loading = False
        self._osint_filter_pending = False
        self._build_osint_catalog_tab()


class OverviewHost(_BaseHost, OverviewTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._overview_loading = False
        self._overview_loaded = False
        self._overview_series_loading = False
        self._overview_series_pending = False
        self._overview_graph_loading = False
        self._overview_companies_loading = False
        self._overview_assign_loading = False
        self._build_overview_tab()


class IacHost(_BaseHost, IacTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._build_iac_tab()


class AuditRunsHost(_BaseHost, AuditRunsTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._build_audit_runs_tab()


class MissionsHost(_BaseHost, MissionsTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._build_missions_tab()


class EngagementsHost(_BaseHost, EngagementsTabMixin, DashboardTabMixin):
    def __init__(self):
        super().__init__()
        self._build_engagement_tab()


# ── e2e hosts: synchronous _run_async so QTest clicks drive the full chain ───────

class FindingsE2EHost(_SyncRunMixin, FindingsHost):
    """FindingsHost whose _run_async runs inline (for click-driven e2e tests)."""


class MissionsE2EHost(_SyncRunMixin, MissionsHost):
    """MissionsHost whose _run_async runs inline (for click-driven e2e tests)."""
