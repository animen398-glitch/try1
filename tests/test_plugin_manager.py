"""Tests for the tab plugin registry and external discovery."""

import pytest

from gui.plugin_manager import BUILTIN_TABS, PluginManager, TabPlugin, default_manager


def _stub(_id, title="T"):
    return TabPlugin(_id, title, lambda window: None)


def test_default_manager_has_all_builtins():
    mgr = default_manager()
    assert len(mgr) == len(BUILTIN_TABS)
    # IA grouping (F-IA): Dashboard leads, System is the last (bottom) utility.
    assert mgr.ids()[0] == "dashboard"
    assert mgr.ids()[-1] == "system"
    # Every built-in keeps a stable id (no tab dropped by the regrouping).
    assert set(mgr.ids()) == {t[0] for t in BUILTIN_TABS}


def test_builtin_tabs_carry_section_and_position():
    mgr = default_manager()
    by_id = {p.id: p for p in mgr}
    assert by_id['dashboard'].section == 'Обзор'
    assert by_id['system'].section == 'Система'
    # All tabs stay in the TOP nav area — the BOTTOM rail is the footer menu.
    assert all(p.position == 'top' for p in mgr)


def _grouped_manager():
    """A manager with stub factories (no MainWindow needed) but real sections."""
    mgr = PluginManager()
    mgr.register(TabPlugin('a', 'A', lambda w: None, section='S1', position='top'))
    mgr.register(TabPlugin('b', 'B', lambda w: None, section='S1', position='top'))
    mgr.register(TabPlugin('c', 'C', lambda w: None, section='S2', position='top'))
    mgr.register(TabPlugin('z', 'Z', lambda w: None, section='Sys', position='bottom'))
    return mgr


def test_build_into_passes_grouping_hints():
    class _Facade:
        def __init__(self):
            self.calls = []

        def addTab(self, widget, title, position='top', new_section=False):
            self.calls.append((title, position, new_section))

    facade = _Facade()
    _grouped_manager().build_into(None, facade)
    by_title = {c[0]: c for c in facade.calls}
    assert by_title['A'][2] is False        # first tab never starts a separator
    assert by_title['B'][2] is False        # same section as A → no separator
    assert by_title['C'][2] is True         # S1 → S2 → separator
    assert by_title['Z'][1] == 'bottom'     # bottom-anchored utility tab


def test_build_into_falls_back_for_plain_addtab():
    # A tab widget whose addTab takes only (widget, title) still works.
    class _Plain:
        def __init__(self):
            self.titles = []

        def addTab(self, widget, title):
            self.titles.append(title)

    plain = _Plain()
    _grouped_manager().build_into(None, plain)
    assert plain.titles == ['A', 'B', 'C', 'Z']


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
