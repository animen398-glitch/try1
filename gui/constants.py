"""Shared filesystem locations for the GUI.

Kept in one place so the main window and the per-tab mixin modules reference
the same paths without importing each other (avoids circular imports).
"""

from pathlib import Path

_ROOT = Path(__file__).parent.parent

SETTINGS_FILE = _ROOT / 'configs' / 'settings.json'
TARGETS_FILE = _ROOT / 'configs' / 'targets.json'
OPERATIONS_DB = _ROOT / 'data' / 'operations.db'
REGISTRY_DB = _ROOT / 'data' / 'registry.db'
LIVE_TEST_OUTPUT = _ROOT / 'live_test_output'
PLUGINS_DIR = _ROOT / 'plugins'  # external tab plugins auto-discovered at startup
