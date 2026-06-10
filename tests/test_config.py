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
