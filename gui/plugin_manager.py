"""gui/plugin_manager.py
A lightweight registry that turns each GUI tab into a registrable "plugin".

Background: the tab UIs were extracted out of the main_window.py monolith into
per-tab mixin modules (gui/tab_*.py). This manager is the next seam — instead
of MainWindow hard-coding an addTab() list, the ordered set of tabs lives in a
PluginManager. That gives a single place to:

  • reorder / enable / disable tabs,
  • register optional or future external tabs without editing MainWindow,
  • introspect what tabs exist.

A TabPlugin pairs a stable ``id`` and display ``title`` with a ``factory`` that
builds the tab's QWidget given the MainWindow. Built-in tabs wrap the existing
mixin ``_build_*_tab`` methods; an external/optional tab is added by calling
``manager.register(TabPlugin(...))`` before the window builds its tabs.
"""

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Union

from qtpy.QtWidgets import QWidget


@dataclass(frozen=True)
class TabPlugin:
    """One registrable tab.

    factory(main_window) -> QWidget. Kept as a callable (not a prebuilt widget)
    so tabs are constructed lazily, in registration order, against the window.

    ``section``/``position`` are optional IA-grouping hints (back-compatible —
    external plugins keep constructing ``TabPlugin(id, title, factory)``): the
    Fluent nav inserts a separator when the ``section`` changes, and
    ``position='bottom'`` anchors utility tabs to the bottom of the rail.
    """
    id: str
    title: str
    factory: Callable[[object], QWidget]
    section: str = ''
    position: str = 'top'


class PluginManager:
    """Ordered registry of TabPlugins."""

    def __init__(self) -> None:
        self._plugins: List[TabPlugin] = []

    def register(self, plugin: TabPlugin) -> None:
        if any(p.id == plugin.id for p in self._plugins):
            raise ValueError(f"duplicate tab plugin id: {plugin.id!r}")
        self._plugins.append(plugin)

    def unregister(self, plugin_id: str) -> None:
        self._plugins = [p for p in self._plugins if p.id != plugin_id]

    def ids(self) -> List[str]:
        return [p.id for p in self._plugins]

    def __iter__(self) -> Iterator[TabPlugin]:
        return iter(self._plugins)

    def __len__(self) -> int:
        return len(self._plugins)

    def build_into(self, window, tab_widget) -> None:
        """Construct every registered tab into ``tab_widget``, in order.

        Passes the IA-grouping hints (``section`` transition → ``new_section``,
        ``position``) to a facade that accepts them; falls back to the plain
        two-arg ``addTab`` for a generic tab widget (the plugin contract)."""
        last_section = None
        for plugin in self._plugins:
            section = getattr(plugin, 'section', '') or ''
            position = getattr(plugin, 'position', 'top') or 'top'
            new_section = bool(section) and last_section is not None \
                and section != last_section
            widget = plugin.factory(window)
            try:
                tab_widget.addTab(widget, plugin.title, position=position,
                                  new_section=new_section)
            except TypeError:
                tab_widget.addTab(widget, plugin.title)
            last_section = section or last_section

    def discover(self, directory: Union[str, Path],
                 on_error: Optional[Callable[[str, Exception], None]] = None
                 ) -> List[str]:
        """Import external tab plugins from ``directory`` and register them.

        Every top-level ``*.py`` file (excluding names starting with ``_``) is
        imported in filename order. A plugin module registers tabs by exposing
        one of, in priority order:

          • ``register(manager)``  — called with this PluginManager;
          • ``TAB_PLUGINS``        — an iterable of TabPlugin;
          • ``TAB_PLUGIN``         — a single TabPlugin.

        A module that raises (or registers nothing valid) is skipped and
        reported via ``on_error(filename, exception)`` — a broken plugin never
        crashes the host. Returns the ids of newly registered tabs.
        """
        directory = Path(directory)
        newly: List[str] = []
        if not directory.is_dir():
            return newly

        for path in sorted(directory.glob('*.py')):
            if path.name.startswith('_'):
                continue
            before = len(self._plugins)
            try:
                module = self._load_module(path)
                if hasattr(module, 'register') and callable(module.register):
                    module.register(self)
                elif hasattr(module, 'TAB_PLUGINS'):
                    for plugin in module.TAB_PLUGINS:
                        self.register(plugin)
                elif hasattr(module, 'TAB_PLUGIN'):
                    self.register(module.TAB_PLUGIN)
                else:
                    raise AttributeError(
                        "plugin must define register(manager), TAB_PLUGIN or "
                        "TAB_PLUGINS"
                    )
            except Exception as e:  # noqa: BLE001 — isolate untrusted plugin code
                # Roll back any partial registration from this module.
                del self._plugins[before:]
                if on_error is not None:
                    on_error(path.name, e)
                continue
            newly.extend(self.ids()[before:])
        return newly

    @staticmethod
    def _load_module(path: Path):
        spec = importlib.util.spec_from_file_location(f"saa_plugin_{path.stem}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load plugin spec from {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


def _mixin_factory(build_method: str) -> Callable[[object], QWidget]:
    """Wrap a MainWindow ``_build_*_tab`` mixin method as a plugin factory."""
    return lambda window: getattr(window, build_method)()


# Built-in tabs: (id, display title, MainWindow build-method, section, position).
# Order here is the order tabs appear in the window — the single source of truth
# for the tab bar. ``section`` clusters the Fluent nav (a separator is drawn when
# it changes). Grouped IA (overview → discovery → security → management → reports
# → tools → system) without merging or removing any tab (the plugin contract is
# unchanged). NOTE: all tabs stay in the TOP (scrollable) nav area — the BOTTOM
# of the rail is reserved for the app-level footer menu (Настройки/О программе/
# Выход, see WindowChromeMixin._build_menu); anchoring tabs there would push the
# menu off-screen. ``position`` is kept on TabPlugin for future use.
BUILTIN_TABS = [
    ("dashboard",  "Dashboard",                 "_build_dashboard_tab", "Обзор", "top"),
    ("overview",   "Overview",                  "_build_overview_tab",  "Обзор", "top"),
    ("recon",      "Recon & Intel",             "_build_recon_tab",     "Разведка", "top"),
    ("subdomain",  "Subdomain Scanner",         "_build_subdomain_tab", "Разведка", "top"),
    ("api",        "API Key Scanner",           "_build_api_tab",       "Разведка", "top"),
    ("capture",    "Site Capture",              "_build_capture_tab",   "Разведка", "top"),
    ("security",   "Security Audit",            "_build_security_tab",  "Безопасность", "top"),
    ("cookie",     "Cookie Security Audit",     "_build_cookie_tab",    "Безопасность", "top"),
    ("findings",   "Findings",                  "_build_findings_tab",  "Управление", "top"),
    ("remediation", "Remediation",              "_build_remediation_tab", "Управление", "top"),
    ("intelligence", "Priorities",              "_build_intelligence_tab", "Управление", "top"),
    ("criticality", "Asset Criticality",        "_build_criticality_tab", "Управление", "top"),
    ("exposure",   "Asset Exposure",            "_build_exposure_tab",  "Управление", "top"),
    ("attackpaths", "Attack Paths",             "_build_attack_paths_tab", "Управление", "top"),
    ("accuracy",   "Scan Accuracy",             "_build_accuracy_tab",  "Управление", "top"),
    ("techrisk",   "Technology Risk",           "_build_technology_risk_tab", "Управление", "top"),
    ("osintcat",   "OSINT Catalog",             "_build_osint_catalog_tab", "Управление", "top"),
    ("auditruns",  "Audit Runs",                "_build_audit_runs_tab", "Управление", "top"),
    ("missions",   "Missions",                  "_build_missions_tab", "Управление", "top"),
    ("iac",        "IaC Config",                "_build_iac_tab",      "Управление", "top"),
    ("assets",     "Assets",                    "_build_assets_tab",    "Управление", "top"),
    ("timeline",   "Timeline",                  "_build_timeline_tab",  "Управление", "top"),
    ("collection", "Final Report & Collection", "_build_collection_tab", "Отчёты", "top"),
    ("clone",      "Clone Frontend",            "_build_clone_tab",     "Инструменты", "top"),
    ("video",      "Video Downloader",          "_build_video_tab",     "Инструменты", "top"),
    ("image",      "Image Extractor",           "_build_image_tab",     "Инструменты", "top"),
    ("design",     "Design Lab",                "_build_design_tab",    "Инструменты", "top"),
    ("history",    "История операций",          "_build_history_tab",   "Система", "top"),
    ("system",     "System",                    "_build_system_tab",    "Система", "top"),
]


def default_manager() -> PluginManager:
    """A PluginManager pre-loaded with the built-in tabs in display order."""
    manager = PluginManager()
    for tab_id, title, build_method, section, position in BUILTIN_TABS:
        manager.register(TabPlugin(tab_id, title, _mixin_factory(build_method),
                                   section=section, position=position))
    return manager
