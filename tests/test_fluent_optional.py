"""qfluentwidgets is an optional (GPL-3.0) dependency: the GUI must build fully
without it. The public release ships without qfluentwidgets (see
THIRD_PARTY_NOTICES.md / RELEASE_CHECKLIST.md); gui/_fluent.py supplies text-only
fallbacks so the native QMainWindow shell stays fully usable.

Driven in a subprocess (mirroring test_self_check) so the absent-package state is
fully isolated — blocking the import in-process would corrupt gui module state
shared with the rest of the suite.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

# Bootstrap: mark qfluentwidgets as absent (a None entry makes `import
# qfluentwidgets` raise ImportError), then run the real --self-check entry point.
_BOOTSTRAP = (
    "import sys, runpy;"
    "sys.modules['qfluentwidgets'] = None;"
    "sys.argv = [{main!r}, '--self-check'];"
    "runpy.run_path({main!r}, run_name='__main__')"
)


def test_self_check_builds_without_qfluentwidgets(tmp_path):
    main = str(_ROOT / "main.py")
    env = dict(os.environ,
               ASA_DATA_ROOT=str(tmp_path / "data"),
               QT_QPA_PLATFORM="offscreen")
    proc = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP.format(main=main)],
        capture_output=True, text=True, timeout=180, env=env, cwd=str(_ROOT),
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    assert "self-check OK" in proc.stdout, proc.stdout
    match = re.search(r"self-check OK.*?(\d+) tab", proc.stdout)
    assert match, proc.stdout
    assert int(match.group(1)) >= 20      # every tab still builds, text-only nav
