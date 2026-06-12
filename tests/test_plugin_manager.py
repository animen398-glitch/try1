"""Tests for the tab plugin registry and external discovery."""

import pytest

from gui.plugin_manager import BUILTIN_TABS, PluginManager, TabPlugin, default_manager


def _stub(_id, title="T"):
    return TabPlugin(_id, title, lambda window: None)


def test_default_manager_has_all_builtins():
    mgr = default_manager()
    assert len(mgr) == len(BUILTIN_TABS)
    assert mgr.ids()[0] == "recon"
    assert mgr.ids()[-1] == "system"


def test_register_and_unregister():
    mgr = PluginManager()
    mgr.register(_stub("a"))
    mgr.register(_stub("b"))
    assert mgr.ids() == ["a", "b"]
    mgr.unregister("a")
    assert mgr.ids() == ["b"]


def test_duplicate_id_rejected():
    mgr = PluginManager()
    mgr.register(_stub("x"))
    with pytest.raises(ValueError):
        mgr.register(_stub("x"))


def test_discover_missing_dir_is_noop(tmp_path):
    mgr = PluginManager()
    assert mgr.discover(tmp_path / "nope") == []


def test_discover_registers_and_isolates_failures(tmp_path):
    (tmp_path / "good.py").write_text(
        "from gui.plugin_manager import TabPlugin\n"
        "def register(m):\n"
        "    m.register(TabPlugin('ext_good', 'Ext Good', lambda w: None))\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    (tmp_path / "_skip.py").write_text("raise RuntimeError('nope')\n", encoding="utf-8")

    errors = []
    mgr = PluginManager()
    new = mgr.discover(tmp_path, on_error=lambda name, exc: errors.append(name))

    assert new == ["ext_good"]
    assert "ext_good" in mgr.ids()
    assert errors == ["broken.py"]            # _skip.py ignored, broken reported


def test_discover_supports_tab_plugin_attribute(tmp_path):
    (tmp_path / "single.py").write_text(
        "from gui.plugin_manager import TabPlugin\n"
        "TAB_PLUGIN = TabPlugin('single', 'Single', lambda w: None)\n",
        encoding="utf-8",
    )
    mgr = PluginManager()
    assert mgr.discover(tmp_path) == ["single"]
