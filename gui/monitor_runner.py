"""gui/monitor_runner.py
In-app Continuous Monitoring adapter (roadmap F3, task T3.2).

Wires ``core.monitor.MonitorScheduler`` into the running GUI so monitoring
actually happens while the app is open (opt-in via ``monitor_autostart``). The
OS-level adapter for true background watching is ``monitor_cli.py`` (``run`` /
``watch``).

Thin by design (I4): the scheduler runs entirely in core on its own daemon
thread; the *only* GUI touch is a Qt signal that marshals each run event from
that background thread onto the GUI thread (cross-thread signals queue safely,
so no widget is touched off-thread).
"""

from pathlib import Path

from qtpy.QtCore import QObject, Signal
from qtpy.QtWidgets import QLabel

from core import monitor
from core.project import ProjectStore


class _MonitorBridge(QObject):
    """Marshals scheduler events (fired on the background thread) onto the GUI
    thread via a queued signal."""

    event = Signal(dict)


class MonitorRunnerMixin:
    """Owns the in-app MonitorScheduler lifecycle. Folded into MainWindow."""

    def _init_monitor_runner(self) -> None:
        """Set up the event bridge + a status-bar indicator. Call once, after the
        status bar is built; autostarts the scheduler when enabled in settings."""
        self._monitor_scheduler = None
        self._monitor_bridge = _MonitorBridge()
        self._monitor_bridge.event.connect(self._on_monitor_event)
        self.monitor_indicator = QLabel("")
        self.monitor_indicator.setStyleSheet("color:#8b949e;padding-right:8px;")
        if getattr(self, 'status_bar', None) is not None:
            self.status_bar.addPermanentWidget(self.monitor_indicator)
        if self.settings.get('monitor_autostart'):
            self._start_monitor_scheduler()

    def _monitor_store(self) -> ProjectStore:
        base = self.settings.get('output_dir') or str(Path.home() / 'SiteAnalyzer')
        return ProjectStore(base)

    def _monitor_running(self) -> bool:
        return (self._monitor_scheduler is not None
                and self._monitor_scheduler.running())

    def _start_monitor_scheduler(self) -> bool:
        """Start the background watcher (idempotent). Returns True if it started."""
        if self._monitor_running():
            return False
        try:
            interval = float(self.settings.get('monitor_check_interval', 1800)
                             or 1800)
        except (TypeError, ValueError):
            interval = 1800.0
        alert_cfg = self.settings.get('alerts')
        alert_cfg = (alert_cfg if isinstance(alert_cfg, dict)
                     and alert_cfg.get('enabled') else None)
        self._monitor_scheduler = monitor.MonitorScheduler(
            self._monitor_store(), check_interval=interval,
            on_event=self._monitor_bridge.event.emit, alert_config=alert_cfg,
            extra_tick=self._tick_due_missions)
        self._monitor_scheduler.start()
        self._update_monitor_indicator()
        return True

    def _tick_due_missions(self, now=None) -> None:
        """Scheduler extra pass (M10): run due Mission Center missions, surfacing
        each via the same event bridge as project monitors. Runs on the daemon
        thread; emits are marshalled onto the GUI thread by the queued signal."""
        from core.mission_schedule import run_due_missions
        run_due_missions(now=now, on_event=self._monitor_bridge.event.emit)

    def _stop_monitor_scheduler(self) -> None:
        if self._monitor_scheduler is not None:
            self._monitor_scheduler.stop()
        self._update_monitor_indicator()

    def _update_monitor_indicator(self) -> None:
        if getattr(self, 'monitor_indicator', None) is None:
            return
        self.monitor_indicator.setText(
            "👁 Мониторинг" if self._monitor_running() else "")

    def _on_monitor_event(self, ev: dict) -> None:
        """GUI-thread slot: surface a scheduler run event (shared formatter)."""
        text = monitor.format_event(ev)
        if getattr(self, 'status_bar', None) is not None:
            self.status_bar.showMessage(text, 10000)
        # Mirror onto the Collection tab's monitor label when present.
        label = getattr(self, 'monitor_status', None)
        if label is not None:
            label.setText(text)
