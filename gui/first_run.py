"""gui/first_run.py — first-run onboarding + system-health screen.

A thin GUI front-end over ``core.launcher.health_check`` (the existing,
offline health engine — never re-derived here). On the very first launch it
shows a one-time health + onboarding dialog; the same dialog is reachable any
time from the navigation footer ("Состояние системы").

The report *formatting* is a pure function (``health_report_text``) so it is
unit-tested without Qt; only the dialog presentation needs a widget.
"""
from pathlib import Path
from typing import Optional


def is_first_run() -> bool:
    """True when no settings.json exists yet (a fresh install / data dir)."""
    from core.config import SETTINGS_FILE
    return not Path(SETTINGS_FILE).exists()


def _mark_first_run_done() -> None:
    """Persist current settings so the onboarding does not show again."""
    from core.config import load_settings, save_settings
    save_settings(load_settings())


def health_report_text(health: dict) -> str:
    """Human-readable health summary (pure). ``health`` is the dict from
    ``core.launcher.health_check``."""
    lines = [f"Python: {health.get('python_version', '?')}"]
    ok = '✓' if health.get('data_root_writable') else '✗'
    lines.append(f"Каталог данных доступен на запись: {ok}")

    lines.append("")
    lines.append("Обязательные зависимости:")
    for r in health.get('required', []):
        mark = '✓' if r.get('ok') else '✗'
        lines.append(f"  {mark} {r.get('name')}")

    optional = health.get('optional') or {}
    present = [n for n, info in optional.items()
               if (info.get('available') if isinstance(info, dict) else info)]
    missing = [n for n in optional if n not in present]
    lines.append("")
    lines.append(f"Опциональные возможности: {len(present)}/{len(optional)} доступно")
    if missing:
        lines.append("  Отсутствуют (фичи деградируют мягко): "
                     + ", ".join(sorted(missing)))

    lines.append("")
    lines.append("Состояние: " + ("ГОТОВ К РАБОТЕ ✓" if health.get('ok')
                                   else "НЕ ХВАТАЕТ ОБЯЗАТЕЛЬНЫХ ЗАВИСИМОСТЕЙ ✗"))
    return "\n".join(lines)


def show_health_dialog(parent, *, health: Optional[dict] = None,
                       onboarding: bool = False) -> None:
    """Show the system-health dialog. ``health`` is injectable for tests; by
    default it is computed from ``core.launcher.health_check``."""
    from qtpy.QtCore import Qt
    from qtpy.QtWidgets import QMessageBox
    from core.launcher import health_check
    health = health if health is not None else health_check()

    text = health_report_text(health)
    if onboarding:
        text = ("Добро пожаловать в Advanced Site Analyzer.\n"
                "Инструмент для АВТОРИЗОВАННОГО анализа безопасности.\n\n"
                + text
                + "\n\nНастройки и каталог проектов — в разделе «Настройки».")
    box = QMessageBox(parent)
    box.setWindowTitle("Состояние системы")
    box.setIcon(QMessageBox.Information if health.get('ok')
                else QMessageBox.Warning)
    box.setText(text)
    # Let the user select & copy the health report (versions, missing deps).
    box.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
    box.exec()


def maybe_show_first_run(parent) -> bool:
    """If this is the first run, show the onboarding+health dialog once and mark
    it done. Returns True if the dialog was shown."""
    if not is_first_run():
        return False
    show_health_dialog(parent, onboarding=True)
    _mark_first_run_done()
    return True
