"""gui/_fluent.py — single import chokepoint for qfluentwidgets (variant B).

Importing ``qfluentwidgets`` prints a one-line promo banner to stdout at package
import time (a bare ``print(ALERT)`` in ``qfluentwidgets/common/config.py``, run on
first import). That pollutes GUI/CLI/test output. Routing *every* qfluentwidgets
import in the app through this module means the package is imported exactly once,
with stdout silenced for the duration, so the banner is swallowed without patching
the third-party package (which would not survive a reinstall or the frozen build).

Add any further qfluentwidgets symbols the app needs here rather than importing
``qfluentwidgets`` directly elsewhere — that keeps this the sole importer and the
banner suppressed.

**Optional dependency.** qfluentwidgets is GPL-3.0; the public release ships
without it (see ``THIRD_PARTY_NOTICES.md`` / ``RELEASE_CHECKLIST.md``). When it is
absent this module supplies lightweight fallbacks: the side-navigation renders as
text-only buttons (null icons) and the third-party theme sync becomes a no-op. The
native ``QMainWindow`` shell (``gui.fluent_nav.StableWindowBase``) does not depend
on qfluentwidgets, so the whole GUI stays fully usable. ``HAS_FLUENT`` reports
which path is active.
"""

from __future__ import annotations

import contextlib
import io

try:
    # Redirect stdout only for the import: print() writes to sys.stdout, so
    # swapping it swallows the banner. Exceptions and stderr are untouched, so a
    # real import failure still propagates and is caught below.
    with contextlib.redirect_stdout(io.StringIO()):
        from qfluentwidgets import (
            FluentIcon,
            FluentWindow,
            NavigationItemPosition,
            Theme,
            setTheme,
        )
    HAS_FLUENT = True
except ImportError:
    # qfluentwidgets not installed (GPL-free build) — degrade to text-only nav.
    HAS_FLUENT = False
    from qtpy.QtGui import QIcon

    class _NullIcon:
        """Stand-in for a FluentIcon member — renders as an empty ``QIcon`` so the
        nav falls back to a text-only button (see ``fluent_nav._qicon``)."""

        def icon(self, *_a, **_k) -> "QIcon":
            return QIcon()

    class _FluentIconProxy:
        """Any attribute access (``FluentIcon.SETTING``, ``.TAG``, …) resolves to a
        null icon, so existing ``getattr(FluentIcon, name, FluentIcon.TAG)`` lookups
        keep working without qfluentwidgets."""

        def __getattr__(self, _name: str) -> "_NullIcon":
            return _NullIcon()

    FluentIcon = _FluentIconProxy()

    class NavigationItemPosition:
        """Position constants used only for equality/branching in the nav."""

        TOP = 0
        SCROLL = 1
        BOTTOM = 2

    class Theme:
        """Theme constants mirroring qfluentwidgets' enum names."""

        LIGHT = "light"
        DARK = "dark"
        AUTO = "auto"

    def setTheme(*_a, **_k) -> None:
        """No-op: with qfluentwidgets absent there is no third-party theme to sync;
        the app's own QPalette/QSS theming (gui.theme) is unaffected."""
        return None

    class FluentWindow:  # noqa: D401 — placeholder; the shell uses StableWindowBase
        """Unused placeholder kept so the exported symbol exists in the fallback."""

__all__ = [
    "FluentIcon",
    "FluentWindow",
    "HAS_FLUENT",
    "NavigationItemPosition",
    "Theme",
    "setTheme",
]
