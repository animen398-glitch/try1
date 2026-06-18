"""launcher.py
Launcher & Dependency Management — the single entry for Install / Repair / Update /
Launch (EPIC 6, Module 5). A thin front-end over ``core.launcher`` (all the logic,
offline-first, no mandatory update server); this file only parses CLI flags and
draws the optional Qt window.

Usage::

    python launcher.py                 # open the Launcher window (Qt)
    python launcher.py --health        # print a health report, exit
    python launcher.py --components    # list optional components + how to install
    python launcher.py --install NAME  # install one optional component
    python launcher.py --repair        # reinstall required deps
    python launcher.py --update        # offline update (pip upgrade + git pull)
    python launcher.py --launch        # start the main application
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import launcher as engine   # noqa: E402 — after sys.path bootstrap


# ── CLI (testable; pure over the injected/real engine) ───────────────────────

def _print_health(h: dict) -> None:
    print(f"Python {h['python_version']} · data root writable: "
          f"{'yes' if h['data_root_writable'] else 'NO'}")
    print("Required:")
    for r in h['required']:
        print(f"  [{'OK ' if r['ok'] else 'MISS'}] {r['name']}")
    print("Optional:")
    for name, info in h['optional'].items():
        print(f"  [{'OK ' if info['available'] else '-- '}] {name} — {info['enables']}")
    print(f"Status: {'HEALTHY' if h['ok'] else 'PROBLEMS — run --repair'}")


def run_cli(argv: list) -> int:
    """Dispatch a launcher CLI command. Returns a process exit code (0 = ok)."""
    if '--health' in argv:
        h = engine.health_check()
        _print_health(h)
        return 0 if h['ok'] else 1
    if '--components' in argv:
        for name, c in engine.installable_components().items():
            how = ('pip install ' + ' '.join(c['packages']) if c['method'] == 'pip'
                   else f"manual — {c['url']}")
            print(f"  {name} ({c['method']}) — {c['enables']}\n      {how}")
        return 0
    if '--install' in argv:
        i = argv.index('--install')
        name = argv[i + 1] if i + 1 < len(argv) else ''
        res = engine.install_optional(name)
        print(f"{name}: {res.get('status')}"
              + (f" — {res.get('note') or res.get('error') or ''}").rstrip())
        return 0 if res.get('status') in ('ok', 'manual') else 1
    if '--repair' in argv:
        res = engine.repair()
        print(f"Repair: {res['status']}" + (f" — {res['error']}" if res.get('error') else ''))
        return 0 if res['status'] == 'ok' else 1
    if '--update' in argv:
        res = engine.update()
        print(f"Update: {res['status']} ("
              + ", ".join(f"{s['step']}={'ok' if s['ok'] else 'fail'}"
                          for s in res['steps']) + ")")
        return 0 if res['status'] == 'ok' else 1
    if '--launch' in argv:
        res = engine.launch_app()
        print(f"Launch: {res['status']}" + (f" — {res['error']}" if res.get('error') else ''))
        return 0 if res['status'] == 'ok' else 1
    return _run_ui()


# ── Qt UI (Module 5) — thin window over the engine ───────────────────────────

def _build_window():
    """Construct the Launcher window (Qt). Imported lazily so the CLI works without
    a display. Returns a ``QWidget`` with the five Module-5 actions.

    Fast, offline actions (health / components / launch / install-list) run
    synchronously; only Repair (slow pip) runs off the GUI thread via a worker, so
    constructing the window starts no thread."""
    from qtpy.QtCore import QThread
    from qtpy.QtWidgets import (
        QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
    )

    from gui.ui_components import ResultsDisplay, SectionGroupBox

    class _RepairThread(QThread):
        def run(self):
            try:
                r = engine.repair()
                self.result = f"Repair: {r['status']}" + (
                    f" — {r['error']}" if r.get('error') else '')
            except Exception as e:   # noqa: BLE001
                self.result = f'Repair failed: {e}'

    class LauncherWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle('Advanced Site Analyzer — Launcher')
            self.resize(640, 480)
            self._threads = []
            layout = QVBoxLayout(self)
            layout.addWidget(QLabel('<b>Launcher & Dependency Management</b>'))

            actions = SectionGroupBox('Действия')
            row = QHBoxLayout()
            self.buttons = {}
            for key, text, slot in (
                ('launch', 'Launch Application', self.on_launch),
                ('health', 'Check Health', self.on_health),
                ('repair', 'Repair Installation', self.on_repair),
                ('components', 'View Components', self.on_components),
                ('install', 'Install Optional Tools', self.on_install),
            ):
                b = QPushButton(text)
                b.clicked.connect(slot)
                row.addWidget(b)
                self.buttons[key] = b
            actions.setLayout(row)
            layout.addWidget(actions)

            self.results = ResultsDisplay()
            layout.addWidget(self.results)
            self._show(_render_health(engine.health_check()))   # synchronous

        def _show(self, text):
            self.results.append(text)

        def on_health(self):
            self._show(_render_health(engine.health_check()))

        def on_components(self):
            self._show(_render_components(engine.installable_components()))

        def on_install(self):
            self._show(_render_components(engine.installable_components())
                       + '\nУстановка: python launcher.py --install <name>')

        def on_launch(self):
            self._show(f"Launch: {engine.launch_app().get('status')}")

        def on_repair(self):
            self.results.append('… Repair (pip install -r requirements.txt)')
            t = _RepairThread(self)
            t.finished.connect(lambda: self._show(getattr(t, 'result', 'Repair: ?')))
            self._threads.append(t)
            t.start()

    return LauncherWindow()


def _render_health(h: dict) -> str:
    req = ' '.join(f"{r['name']}{'✓' if r['ok'] else '✗'}" for r in h['required'])
    opt_ok = sum(1 for v in h['optional'].values() if v['available'])
    return (f"Health: {'OK' if h['ok'] else 'PROBLEMS'} · Python {h['python_version']}\n"
            f"  Required: {req}\n"
            f"  Optional: {opt_ok}/{len(h['optional'])} available · "
            f"data root writable: {'yes' if h['data_root_writable'] else 'NO'}")


def _render_components(comp: dict) -> str:
    lines = ['Optional components:']
    for name, c in comp.items():
        how = ('pip' if c['method'] == 'pip' else f"manual — {c['url']}")
        lines.append(f"  {name} [{how}] — {c['enables']}")
    return '\n'.join(lines)


def _run_ui() -> int:
    try:
        from qtpy.QtWidgets import QApplication
    except Exception as e:   # noqa: BLE001 — no Qt → fall back to a health report
        print(f'Qt unavailable ({e}); use the CLI flags. Health:')
        return run_cli(['--health'])
    app = QApplication.instance() or QApplication(sys.argv)
    win = _build_window()
    win.show()
    return app.exec()


def main() -> int:
    return run_cli(sys.argv[1:])


if __name__ == '__main__':
    raise SystemExit(main())
