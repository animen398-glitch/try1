"""Shared pytest fixtures.

Runs Qt in headless ``offscreen`` mode and exposes a session-wide QApplication
so widget-building tests work without a display. Pure-logic tests don't need
the ``qapp`` fixture.
"""

import os
import sys
from pathlib import Path

import pytest

# Headless Qt + importable project root, before any Qt import. QT_API pins the
# qtpy binding (PyQt5 today; flip to "pyside6" for the variant-B migration).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_API", "pyside6")
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture(autouse=True)
def _isolate_findings_db(tmp_path_factory, monkeypatch):
    """Redirect the global findings DB to a per-test temp file.

    ``FindingsStore()`` defaults to ``data/findings.db`` (a real repo path).
    Without this, any test that runs a Full Collection or FindingsStore.sync
    would write into the working tree. Tests that need to inspect the store use
    the default ``FindingsStore()`` and land here automatically; tests passing an
    explicit ``db_path`` are unaffected.
    """
    import core.findings_store as fstore
    monkeypatch.setattr(fstore, "FINDINGS_DB",
                        tmp_path_factory.mktemp("findings") / "findings.db")


@pytest.fixture(autouse=True)
def _isolate_assets_db(tmp_path_factory, monkeypatch):
    """Redirect the global assets DB to a per-test temp file.

    ``AssetStore()`` defaults to ``data/assets.db`` (a real repo path); without
    this, any test running a Full Collection or AssetStore.sync would write into
    the working tree (mirrors ``_isolate_findings_db``)."""
    import core.asset_store as astore
    monkeypatch.setattr(astore, "ASSETS_DB",
                        tmp_path_factory.mktemp("assets") / "assets.db")


@pytest.fixture(autouse=True)
def _isolate_companies_registry(tmp_path_factory, monkeypatch):
    """Redirect the global companies registry to a per-test temp file.

    ``CompanyRegistry()`` defaults to ``data/companies.json`` (a real repo path);
    it binds the default at construction from the module name, so patch it there
    (mirrors ``_isolate_findings_db``)."""
    import core.company as company
    monkeypatch.setattr(company, "COMPANIES_REGISTRY",
                        tmp_path_factory.mktemp("companies") / "companies.json")


@pytest.fixture(autouse=True)
def _isolate_operations_db(request, tmp_path_factory, monkeypatch):
    """Redirect the global operations DB to a per-test temp file.

    ``OperationRegistry()`` defaults to ``core.config.OPERATIONS_DB`` (a real repo
    path). Alert deliveries (F4) and any other op logging now land there, so
    without this a test could write into the working tree. ``OperationRegistry``
    reads the default lazily from ``core.config`` at construction, so patching the
    attribute there covers every default-constructed registry. Tests that assert
    the real derived path opt out with ``@pytest.mark.real_operations_db``.
    """
    if request.node.get_closest_marker("real_operations_db"):
        return
    import core.config as cfg
    monkeypatch.setattr(cfg, "OPERATIONS_DB",
                        tmp_path_factory.mktemp("ops") / "operations.db")


@pytest.fixture(scope="session")
def qapp():
    from qtpy.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def _reclaim_qt_objects():
    """Free top-level Qt widgets left behind by each test.

    A parentless QWidget/QMainWindow is owned by QApplication (it lives in
    ``topLevelWidgets()``), so Python GC alone never frees it — its native
    resources persist for the whole session. Widget-building tests therefore
    accumulate windows until, on Windows, the per-process GDI/USER handle pool
    is exhausted and the run aborts partway (silent exit, no traceback).
    ``deleteLater`` + flushing the deferred-delete queue actually reclaims
    them, keeping the whole suite runnable in one process. Tests build their
    own widgets fresh, so deleting last test's leftovers is safe.
    """
    import gc
    yield
    try:
        from qtpy.QtCore import QEvent
        from qtpy.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            for widget in app.topLevelWidgets():
                widget.deleteLater()
            app.sendPostedEvents(None, QEvent.DeferredDelete)
    except Exception:
        pass
    gc.collect()
