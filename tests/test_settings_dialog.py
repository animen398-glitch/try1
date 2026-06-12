"""SettingsDialog persists the UA-profile and archive-format selectors.

Regression: user_agent_profile (read by 8 tabs) and compression_format (read by
archiving) had no UI control, so they were stuck on their defaults.
"""

import pytest

from core import config


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(config, "TARGETS_FILE", tmp_path / "targets.json")
    return tmp_path


def test_dialog_persists_ua_profile_and_archive_format(qapp, isolated_config):
    from gui.dialogs import SettingsDialog

    dlg = SettingsDialog()
    # Both selectors must exist and be populated from the supported lists.
    assert dlg.ua_combo.count() >= 2
    assert {"zip", "rar"}.issubset(
        {dlg.compress_combo.itemText(i) for i in range(dlg.compress_combo.count())})

    dlg.ua_combo.setCurrentText("firefox_windows")
    dlg.compress_combo.setCurrentText("rar")
    dlg._on_accept()

    saved = config.load_settings()
    assert saved["user_agent_profile"] == "firefox_windows"
    assert saved["compression_format"] == "rar"


def test_dialog_expands_tilde_in_output_dir(qapp, isolated_config):
    """A '~/...' output dir must be expanded on save, so a same-session scan
    never writes to a literal '~' folder in the CWD (the 50 GB-folder bug)."""
    import os

    from gui.dialogs import SettingsDialog
    dlg = SettingsDialog()
    dlg.output_dir_edit.setText("~/SiteAnalyzer")
    dlg._on_accept()

    saved = config.load_settings()["output_dir"]
    assert "~" not in saved
    assert saved == os.path.expanduser("~/SiteAnalyzer")


def test_dialog_loads_current_values(qapp, isolated_config):
    from gui.dialogs import SettingsDialog
    config.save_settings({"user_agent_profile": "safari_mac",
                          "compression_format": "rar"})

    dlg = SettingsDialog()
    assert dlg.ua_combo.currentText() == "safari_mac"
    assert dlg.compress_combo.currentText() == "rar"
