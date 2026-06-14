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
"""

from __future__ import annotations

import contextlib
import io

# Redirect stdout only for the import: print() writes to sys.stdout, so swapping it
# swallows the banner. Exceptions and stderr are untouched, so a real import failure
# still propagates normally.
with contextlib.redirect_stdout(io.StringIO()):
    from qfluentwidgets import (
        FluentIcon,
        FluentWindow,
        NavigationItemPosition,
        Theme,
        setTheme,
    )

__all__ = [
    "FluentIcon",
    "FluentWindow",
    "NavigationItemPosition",
    "Theme",
    "setTheme",
]
