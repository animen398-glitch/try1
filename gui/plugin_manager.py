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

from dataclasses import dataclass
from typing import Callable, Iterator, List

from PyQt5.QtWidgets import QWidget


@dataclass(frozen=True)
class TabPlugin:
    """One registrable tab.

    factory(main_window) -> QWidget. Kept as a callable (not a prebuilt widget)
    so tabs are constructed lazily, in registration order, against the window.
    """
    id: str
    title: str
    factory: Callable[[object], QWidget]


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
        """Construct every registered tab into ``tab_widget``, in order."""
        for plugin in self._plugins:
            tab_widget.addTab(plugin.factory(window), plugin.title)


def _mixin_factory(build_method: str) -> Callable[[object], QWidget]:
    """Wrap a MainWindow ``_build_*_tab`` mixin method as a plugin factory."""
    return lambda window: getattr(window, build_method)()


# Built-in tabs: (id, display title, MainWindow build-method). Order here is the
# order tabs appear in the window — the single source of truth for the tab bar.
BUILTIN_TABS = [
    ("recon",      "Recon & Intel",             "_build_recon_tab"),
    ("subdomain",  "Subdomain Scanner",         "_build_subdomain_tab"),
    ("api",        "API Key Scanner",           "_build_api_tab"),
    ("capture",    "Site Capture",              "_build_capture_tab"),
    ("clone",      "Clone Frontend",            "_build_clone_tab"),
    ("video",      "Video Downloader",          "_build_video_tab"),
    ("image",      "Image Extractor",           "_build_image_tab"),
    ("design",     "Design Lab",                "_build_design_tab"),
    ("cookie",     "Cookie Security Audit",     "_build_cookie_tab"),
    ("collection", "Final Report & Collection", "_build_collection_tab"),
    ("dashboard",  "Dashboard",                 "_build_dashboard_tab"),
    ("history",    "История операций",          "_build_history_tab"),
    ("system",     "System",                    "_build_system_tab"),
]


def default_manager() -> PluginManager:
    """A PluginManager pre-loaded with the built-in tabs in display order."""
    manager = PluginManager()
    for tab_id, title, build_method in BUILTIN_TABS:
        manager.register(TabPlugin(tab_id, title, _mixin_factory(build_method)))
    return manager
