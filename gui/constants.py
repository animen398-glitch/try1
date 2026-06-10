"""Shared filesystem locations for the GUI.

Thin re-export of the canonical paths from core.config so existing
``from gui.constants import ...`` imports keep working while there remains a
single source of truth.
"""

from core.config import (  # noqa: F401  (re-exported for backward compatibility)
    LIVE_TEST_OUTPUT,
    OPERATIONS_DB,
    PLUGINS_DIR,
    REGISTRY_DB,
    SETTINGS_FILE,
    TARGETS_FILE,
)
