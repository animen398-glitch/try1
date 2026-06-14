"""Tests for the unified config (settings + targets), isolated to tmp files."""

import json

import pytest

from core import config


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(config, "TARGETS_FILE", tmp_path / "targets.json")
    return tmp_path


def test_load_settings_defaults_when_missing(isolated_config):
    s = config.load_settings()
    assert s["max_pages"] == config.DEFAULT_SETTINGS["max_pages"]
    assert s["user_agent_profile"] == "chrome_windows"
    assert s["compression_format"] == "zip"


def test_load_merges_file_over_defaults(isolated_config):
    (config.SETTINGS_FILE).write_text(
        json.dumps({"max_pages": 7, "extra": "x"}), encoding="utf-8"
    )
    s = config.load_settings()
    assert s["max_pages"] == 7                 # file wins
    assert s["user_agent_profile"] == "chrome_windows"  # default preserved
    assert s["extra"] == "x"                   # unknown keys kept


def test_save_then_load_round_trip(isolated_config):
    assert config.save_settings({"max_pages": 99, "output_dir": "/tmp/x"})
    s = config.load_settings()
    assert s["max_pages"] == 99


def test_load_settings_survives_corrupt_file(isolated_config):
    config.SETTINGS_FILE.write_text("{not json", encoding="utf-8")
    s = config.load_settings()
    assert s["max_pages"] == config.DEFAULT_SETTINGS["max_pages"]


def test_targets_dedup_and_prepend(isolated_config):
    assert config.save_target("https://a.com")
    config.save_target("https://b.com")
    config.save_target("https://a.com")          # duplicate ignored
    targets = config.load_targets()
    assert targets == ["https://b.com", "https://a.com"]


def test_save_empty_target_is_noop(isolated_config):
    assert config.save_target("") is False
    assert config.load_targets() == []


def test_targets_capped(isolated_config, monkeypatch):
    monkeypatch.setattr(config, "MAX_TARGETS", 3)
    for i in range(5):
        config.save_target(f"https://h{i}.com")
    assert len(config.load_targets()) == 3


@pytest.mark.real_operations_db
def test_config_paths_derive_from_path_manager():
    """Writable paths track PathManager.data_root, resources track resource_root.

    Combined with the frozen-detection tests in test_paths.py, this proves a
    frozen .exe redirects DBs/settings to %APPDATA% (data_root) while plugins
    load from the bundle (resource_root) — without rewiring each consumer.
    """
    pm = config.get_path_manager()
    assert config.DATA_DIR == pm.data_root / "data"
    assert config.OPERATIONS_DB == pm.data_root / "data" / "operations.db"
    assert config.REGISTRY_DB == pm.data_root / "data" / "registry.db"
    assert config.CONFIG_DIR == pm.data_root / "configs"
    assert config.SETTINGS_FILE == pm.data_root / "configs" / "settings.json"
    assert config.LIVE_TEST_OUTPUT == pm.data_root / "live_test_output"
    assert config.PLUGINS_DIR == pm.resource_root / "plugins"


def test_operation_registry_default_db_uses_path_manager():
    """OperationRegistry() with no db_path resolves through PathManager.

    Mirrors DataRegistry -> REGISTRY_DB: a frozen .exe must not fall back to a
    CWD-relative 'operations.db', so the bare-default path equals OPERATIONS_DB.
    """
    from utils.operation_registry import OperationRegistry
    assert str(OperationRegistry().db_path) == str(config.OPERATIONS_DB)


def test_system_logger_path_uses_path_manager():
    """The system log resolves under PathManager's data root, not the CWD."""
    from utils.system_logger import _log_file
    pm = config.get_path_manager()
    assert _log_file() == str(pm.data_root / "data" / "system.log")
