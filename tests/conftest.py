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
