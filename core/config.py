"""core/config.py
Single source of truth for filesystem locations, default settings, and the
load/save helpers for settings.json and targets.json.

Everything (GUI, CLI orchestrator, core engines) reads paths and settings from
here so there is one canonical set of defaults and one set of DB locations,
anchored to the project root (not the current working directory).
"""

import json
import os
from pathlib import Path
from typing import List

# PathManager is the frozen-build-aware authority for writable data vs bundled
# resource locations; re-exported here so config stays the one place to reach
# for filesystem locations. See core/paths.py.
from core.paths import (  # noqa: F401
    APP_NAME, PathManager, get_path_manager, init_path_manager,
)

ROOT = Path(__file__).resolve().parent.parent

# Single source of truth for the application version (semver). Surfaced in the
# SARIF tool.driver, CI gate, "About" dialog and future update checks.
APP_VERSION = '1.0.0'

# Writable user data (settings, targets, DBs, live-test output) and read-only
# bundled resources (plugins) resolve through the process-default PathManager,
# so a frozen .exe writes under %APPDATA% instead of the ephemeral _MEIPASS
# extraction dir. In development data_root and resource_root both equal the
# project root, so every path below is byte-for-byte unchanged.
_PM = get_path_manager()

CONFIG_DIR = _PM.data_root / 'configs'
DATA_DIR = _PM.data_root / 'data'

SETTINGS_FILE = CONFIG_DIR / 'settings.json'
TARGETS_FILE = CONFIG_DIR / 'targets.json'
OPERATIONS_DB = DATA_DIR / 'operations.db'
REGISTRY_DB = DATA_DIR / 'registry.db'
FINDINGS_DB = DATA_DIR / 'findings.db'
ASSETS_DB = DATA_DIR / 'assets.db'        # Asset Inventory (cross-scan, lifecycle)
CVE_CACHE_DB = DATA_DIR / 'cve_cache.db'  # CVE Intelligence — persistent OSV/NVD cache (offline)
COMPANIES_REGISTRY = DATA_DIR / 'companies.json'  # Company tier — display names/attrs
LIVE_TEST_OUTPUT = _PM.data_root / 'live_test_output'
PLUGINS_DIR = _PM.resource_root / 'plugins'

DEFAULT_SETTINGS = {
    'output_dir': str(Path.home() / 'SiteAnalyzer'),
    'max_pages': 50,
    'request_delay': 500,
    'user_agent_profile': 'chrome_windows',
    'auto_compress': False,
    'compression_format': 'zip',
    # Alert Center (#9) — opt-in; off until a channel is configured. See
    # core.alerts for the full shape (telegram/discord/email + types filter).
    'alerts': {'enabled': False},
    # Continuous Monitoring (F3) in-app scheduler — opt-in background watcher
    # that runs while the app is open. ``monitor_check_interval`` is seconds
    # between due-checks (the OS-level adapter is monitor_cli.py).
    'monitor_autostart': False,
    'monitor_check_interval': 1800,
    # GUI theme (F6, variant A) — 'system' | 'light' | 'dark'. Default 'system'
    # leaves the current look untouched; only 'dark' overrides the palette.
    # Applied at startup (main.py) via gui.theme.apply_theme.
    'gui_theme': 'system',
    # CVE Intelligence (EPIC 3) — optional NVD API key. Empty = keyless (works,
    # just a lower rate limit); never required (no mandatory cloud dependency).
    'nvd_api_key': '',
}

MAX_TARGETS = 100


def load_settings() -> dict:
    """Defaults merged with the on-disk settings.json (file values win)."""
    data = dict(DEFAULT_SETTINGS)
    try:
        if SETTINGS_FILE.exists():
            on_disk = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
            if isinstance(on_disk, dict):
                data.update(on_disk)
    except Exception:
        pass
    data['output_dir'] = os.path.expanduser(
        data.get('output_dir') or DEFAULT_SETTINGS['output_dir']
    )
    return data


def save_settings(settings: dict) -> bool:
    try:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(
            json.dumps(settings, indent=2, ensure_ascii=False), encoding='utf-8'
        )
        return True
    except Exception:
        return False


def load_targets() -> List[str]:
    try:
        if TARGETS_FILE.exists():
            data = json.loads(TARGETS_FILE.read_text(encoding='utf-8'))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_target(url: str) -> bool:
    """Prepend a target URL to the recent-targets list (deduped, capped)."""
    if not url:
        return False
    try:
        targets = load_targets()
        if url not in targets:
            targets.insert(0, url)
            targets = targets[:MAX_TARGETS]
        TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        TARGETS_FILE.write_text(
            json.dumps(targets, indent=2, ensure_ascii=False), encoding='utf-8'
        )
        return True
    except Exception:
        return False
