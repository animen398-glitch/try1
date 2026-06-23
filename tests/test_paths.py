"""Tests for core.paths.PathManager (filesystem-isolated via tmp_path).

Detection tests drive the frozen/dev branches with monkeypatched sys/env;
getter tests use an explicit data_root so nothing is created in the repo.
"""

import sys

import core.paths as paths
from core.paths import PathManager, get_path_manager, init_path_manager


# ----------------------------------------------------------------- detection

def test_dev_mode_anchors_to_project_root(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    pm = PathManager()
    assert pm.frozen is False
    assert pm.data_root == paths._PROJECT_ROOT
    assert pm.resource_root == paths._PROJECT_ROOT


def test_frozen_uses_meipass_for_resources_and_appdata_for_data(
        monkeypatch, tmp_path):
    meipass = tmp_path / "_MEI12345"
    appdata = tmp_path / "AppData" / "Roaming"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
    monkeypatch.setenv("APPDATA", str(appdata))

    pm = PathManager(app_name="MyApp")
    assert pm.frozen is True
    assert pm.resource_root == meipass                  # bundled, read-only
    assert pm.data_root == appdata / "MyApp"            # writable, persistent


def test_frozen_falls_back_when_appdata_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    pm = PathManager(app_name="MyApp")
    assert pm.data_root == paths.Path.home() / ".myapp"


def test_frozen_honours_xdg_when_no_appdata(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    pm = PathManager(app_name="MyApp")
    assert pm.data_root == tmp_path / "xdg" / "MyApp"


# --------------------------------------------------------- data-root override

def test_env_override_wins_in_dev(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setenv("ASA_DATA_ROOT", str(tmp_path / "demo"))
    pm = PathManager()
    assert pm.data_root == tmp_path / "demo"          # env beats project root


def test_env_override_wins_when_frozen(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "_MEI"), raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    monkeypatch.setenv("ASA_DATA_ROOT", str(tmp_path / "demo"))
    pm = PathManager()
    assert pm.data_root == tmp_path / "demo"          # env beats %APPDATA% too


def test_explicit_data_root_beats_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ASA_DATA_ROOT", str(tmp_path / "env"))
    pm = PathManager(data_root=tmp_path / "explicit")
    assert pm.data_root == tmp_path / "explicit"      # ctor arg is highest


def test_no_env_keeps_dev_default(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.delenv("ASA_DATA_ROOT", raising=False)
    assert PathManager().data_root == paths._PROJECT_ROOT


# ------------------------------------------------------------------- getters

def test_get_db_path_creates_data_dir(tmp_path):
    pm = PathManager(data_root=tmp_path, resource_root=tmp_path)
    db = pm.get_db_path("operations.db")
    assert db == tmp_path / "data" / "operations.db"
    assert db.parent.is_dir()              # parent created, file not yet


def test_get_workspace_path_slugifies_and_creates(tmp_path):
    pm = PathManager(data_root=tmp_path)
    ws = pm.get_workspace_path("https://www.Example.com/path")
    assert ws == tmp_path / "workspaces" / "example.com"
    assert ws.is_dir()


def test_get_temp_path_created(tmp_path):
    pm = PathManager(data_root=tmp_path)
    tmp = pm.get_temp_path()
    assert tmp == tmp_path / "temp"
    assert tmp.is_dir()


def test_get_reports_path_dir_and_file(tmp_path):
    pm = PathManager(data_root=tmp_path)
    reports_dir = pm.get_reports_path()
    assert reports_dir == tmp_path / "reports" and reports_dir.is_dir()

    report_file = pm.get_reports_path("scan", "out.html")
    assert report_file == tmp_path / "reports" / "scan" / "out.html"
    assert report_file.parent.is_dir() and not report_file.exists()


def test_get_resource_path_does_not_create(tmp_path):
    pm = PathManager(resource_root=tmp_path, data_root=tmp_path)
    res = pm.get_resource_path("assets", "logo.png")
    assert res == tmp_path / "assets" / "logo.png"
    assert not res.exists() and not res.parent.exists()   # read-only: no mkdir


def test_slug_edge_cases():
    assert PathManager._slug("") == "unknown"
    assert PathManager._slug("https://sub.Domain.io") == "sub.domain.io"
    assert PathManager._slug("weird name!!") == "weird_name"


# ----------------------------------------------------------------- singleton

def test_singleton_init_and_get(monkeypatch):
    monkeypatch.setattr(paths, "_default", None)
    a = init_path_manager(app_name="Once")
    assert get_path_manager() is a               # same instance returned
    assert a.app_name == "Once"


def test_get_creates_default_lazily(monkeypatch):
    monkeypatch.setattr(paths, "_default", None)
    pm = get_path_manager()
    assert isinstance(pm, PathManager)
    assert get_path_manager() is pm              # cached


def test_reexported_from_config():
    from core import config
    assert config.PathManager is PathManager
