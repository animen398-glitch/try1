"""Shared pytest fixtures.

Runs Qt in headless ``offscreen`` mode and exposes a session-wide QApplication
so widget-building tests work without a display. Pure-logic tests don't need
the ``qapp`` fixture.
"""

import os
import sys
from pathlib import Path

import pytest

# Headless Qt + importable project root, before any PyQt import.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


@pytest.fixture(scope="session")
def qapp():
    from PyQt5.QtWidgets import QApplication
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
        from PyQt5.QtCore import QEvent
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            for widget in app.topLevelWidgets():
                widget.deleteLater()
            app.sendPostedEvents(None, QEvent.DeferredDelete)
    except Exception:
        pass
    gc.collect()
