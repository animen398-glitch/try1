"""core/paths.py

PathManager — the single authority for *where* the application reads bundled
resources and writes user data, with correct behaviour under a frozen
PyInstaller .exe.

It separates two roots that a frozen build must keep apart:

  • resource root — read-only files bundled into the build. Under PyInstaller
    these are unpacked to ``sys._MEIPASS`` (an ephemeral temp dir); running
    from source they live under the project root. Use for shipped assets,
    wordlists, templates, etc.

  • data root — the writable, persistent per-user location for databases,
    reports, per-domain workspaces and scratch/temp. A frozen .exe must NOT
    write next to itself or inside the ephemeral _MEIPASS dir, so this resolves
    to ``%APPDATA%\\<app>`` on Windows (or an OS-appropriate fallback). Running
    from source it stays at the project root, preserving the existing ``data/``
    layout.

Initialise once (e.g. in main.py) via ``init_path_manager()`` and inject the
instance where it is needed; ``get_path_manager()`` returns a lazily-created
default for call sites not yet migrated to injection.
"""

import os
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

APP_NAME = 'AdvancedSiteAnalyzer'

# Environment override for the writable-data root. When set, it wins over both
# the source-tree and frozen-%APPDATA% defaults — every DB, config, report and
# workspace then lives under that one directory. This is the seam a portable /
# demo workspace uses: point the app at a self-contained folder without touching
# the user's real data/ (see demo_seed.py). An explicit ``data_root=`` ctor arg
# (used by tests) still takes precedence over the env var.
DATA_ROOT_ENV = 'ASA_DATA_ROOT'

# Project root when running from source: …/core/paths.py -> project root.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class PathManager:
    """Resolves resource and writable-data locations, frozen-build aware.

    Args:
        app_name:      folder name used under %APPDATA% (frozen builds).
        data_root:     override the writable-data root (mainly for tests).
        resource_root: override the bundled-resource root (mainly for tests).
    """

    def __init__(self, app_name: str = APP_NAME,
                 data_root: Optional[os.PathLike] = None,
                 resource_root: Optional[os.PathLike] = None):
        self.app_name = app_name
        # PyInstaller sets sys.frozen=True and unpacks data to sys._MEIPASS.
        self.frozen = bool(getattr(sys, 'frozen', False))
        self._resource_root = (
            Path(resource_root) if resource_root is not None
            else self._detect_resource_root()
        )
        self._data_root = (
            Path(data_root) if data_root is not None
            else self._detect_data_root()
        )

    # ----------------------------------------------------------- detection

    def _detect_resource_root(self) -> Path:
        meipass = getattr(sys, '_MEIPASS', None)
        if self.frozen and meipass:
            return Path(meipass)
        return _PROJECT_ROOT

    def _detect_data_root(self) -> Path:
        # An explicit env override wins everywhere (portable / demo workspace);
        # it lets the app run against a self-contained data dir without touching
        # the real one. Otherwise: a frozen .exe must write to a stable,
        # user-writable location — never the ephemeral _MEIPASS extraction dir;
        # from source, keep the existing project-root data layout so nothing
        # moves during development.
        override = os.getenv(DATA_ROOT_ENV)
        if override:
            return Path(override).expanduser()
        if self.frozen:
            return self._user_data_base()
        return _PROJECT_ROOT

    def _user_data_base(self) -> Path:
        """Per-user writable base: %APPDATA%\\<app> on Windows, else fallbacks."""
        appdata = os.getenv('APPDATA')            # Windows roaming profile
        if appdata:
            return Path(appdata) / self.app_name
        xdg = os.getenv('XDG_DATA_HOME')          # Linux XDG base dir spec
        if xdg:
            return Path(xdg) / self.app_name
        return Path.home() / f'.{self.app_name.lower()}'   # last-resort dotdir

    # -------------------------------------------------------------- roots

    @property
    def data_root(self) -> Path:
        """Writable base for DBs / reports / workspaces / temp."""
        return self._data_root

    @property
    def resource_root(self) -> Path:
        """Read-only base for bundled resources (sys._MEIPASS when frozen)."""
        return self._resource_root

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _slug(domain: str) -> str:
        """Filesystem-safe per-domain folder name."""
        netloc = urlparse(domain).netloc or domain.split('/')[0]
        netloc = netloc.replace('www.', '').strip().lower()
        safe = ''.join(c if (c.isalnum() or c in '.-_') else '_' for c in netloc)
        return safe.strip('._') or 'unknown'

    # ----------------------------------------------------------- public API

    def get_resource_path(self, *parts: str) -> Path:
        """Path to a bundled, read-only resource (no directory is created)."""
        return self._resource_root.joinpath(*parts)

    def get_db_path(self, name: str) -> Path:
        """Path to a database file under the writable data root.

        Ensures the parent ``data/`` directory exists so callers can open the
        DB straight away.
        """
        data_dir = self._data_root / 'data'
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / name

    def get_workspace_path(self, domain: str) -> Path:
        """Per-domain output directory (created); ``domain`` is slugified."""
        path = self._data_root / 'workspaces' / self._slug(domain)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_reports_path(self, *parts: str) -> Path:
        """Directory (or file path) under the writable reports/ tree (created)."""
        base = self._data_root / 'reports'
        target = base.joinpath(*parts) if parts else base
        # Create the directory itself when no filename component is given,
        # otherwise create its parent so the file can be written.
        (target if not parts else target.parent).mkdir(parents=True, exist_ok=True)
        return target

    def get_temp_path(self) -> Path:
        """App scratch directory under the writable data root (created)."""
        path = self._data_root / 'temp'
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_crash_dir(self) -> Path:
        """Directory for local crash reports under the writable data root
        (created). Frozen-aware like the DB/temp dirs so the reports land in the
        %APPDATA% data root, not the ephemeral PyInstaller extraction dir."""
        path = self._data_root / 'data' / 'crashes'
        path.mkdir(parents=True, exist_ok=True)
        return path


# --------------------------------------------------------------- singleton

_default: Optional[PathManager] = None


def init_path_manager(**kwargs) -> PathManager:
    """Create (or replace) the process-wide default PathManager. Call once,
    early (e.g. in main.py), then inject the returned instance."""
    global _default
    _default = PathManager(**kwargs)
    return _default


def get_path_manager() -> PathManager:
    """Return the process-wide default PathManager, creating a vanilla one on
    first use. Lets not-yet-injected call sites share one instance."""
    global _default
    if _default is None:
        _default = PathManager()
    return _default
