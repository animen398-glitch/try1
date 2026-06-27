"""Packaging smoke: `main.py --self-check` builds the window headless and exits 0.

This drives the *real* entry point (init_path_manager → QApplication →
MainWindow) the way the frozen .exe does, so it catches import/wiring breakage
that constructing MainWindow inside the test process might mask. CI runs the
same flag against the built .exe to catch PyInstaller-only regressions."""

import os
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_self_check_exits_zero_and_reports_tabs(tmp_path):
    data_root = tmp_path / "self-check-data"
    env = dict(os.environ, ASA_DATA_ROOT=str(data_root), QT_QPA_PLATFORM="offscreen")
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "main.py"), "--self-check"],
        capture_output=True, text=True, timeout=180, env=env, cwd=str(_ROOT),
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    assert "self-check OK" in proc.stdout
    match = re.search(r"self-check OK.*?(\d+) tab", proc.stdout)
    assert match, proc.stdout
    assert int(match.group(1)) >= 20
