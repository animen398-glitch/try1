"""gui/crash_dialog.py — startup surface for unseen crash reports.

Thin GUI over :mod:`core.crash_reporter`: on launch, if the previous session
left an unseen (already-redacted) crash report, offer to view / copy / (only if
an endpoint is configured) send it, then mark it seen. All decisions and data
live in the core module; this file only renders them.
"""

from qtpy.QtWidgets import (
    QApplication, QDialog, QMessageBox, QPushButton, QTextEdit, QVBoxLayout,
)


def _format_reports(reports) -> str:
    """Human-readable, copyable text for the pending reports."""
    blocks = []
    for r in reports:
        blocks.append(
            f"=== {r.get('kind', '?')} @ {r.get('time', '?')} ===\n"
            f"app {r.get('app_version', '?')} · {r.get('os', '?')} · "
            f"python {r.get('python', '?')} · qt {r.get('qt', '?')}\n\n"
            f"{r.get('detail', '')}\n"
            f"breadcrumbs:\n  " + "\n  ".join(r.get('breadcrumbs', []))
        )
    return "\n\n".join(blocks)


def _show_detail(parent, text: str) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle("Crash report")
    dlg.resize(720, 480)
    layout = QVBoxLayout(dlg)
    view = QTextEdit()
    view.setReadOnly(True)
    view.setPlainText(text)
    layout.addWidget(view)
    close = QPushButton("Закрыть")
    close.clicked.connect(dlg.accept)
    layout.addWidget(close)
    dlg.exec()


def maybe_show_crash_dialog(parent=None) -> bool:
    """Show unseen crash reports (if any) and mark them seen. Returns whether a
    dialog was shown. Safe to call unconditionally at startup."""
    from core import crash_reporter
    from core.config import load_settings

    cfg = load_settings().get('crash_reporting', {}) or {}
    if not cfg.get('enabled', True):
        return False

    pending = crash_reporter.pending_crashes()
    if not pending:
        return False

    text = _format_reports(pending)
    endpoint = str(cfg.get('endpoint', '') or '')

    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Warning)
    box.setWindowTitle("Прошлый сеанс завершился аварийно")
    box.setText(f"Обнаружено аварийных отчётов: {len(pending)}.\n"
                "Отчёт сохранён локально (секреты вырезаны). Ничего не "
                "отправляется без вашего действия.")
    view_btn = box.addButton("Посмотреть", QMessageBox.ActionRole)
    copy_btn = box.addButton("Копировать", QMessageBox.ActionRole)
    send_btn = box.addButton("Отправить", QMessageBox.ActionRole) if endpoint else None
    box.addButton("Пропустить", QMessageBox.RejectRole)
    box.exec()

    clicked = box.clickedButton()
    if clicked is view_btn:
        _show_detail(parent, text)
    elif clicked is copy_btn:
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(text)
    elif send_btn is not None and clicked is send_btn:
        ok_count = sum(
            1 for r in pending if crash_reporter.send_report(r, endpoint)[0])
        QMessageBox.information(
            parent, "Отправка",
            f"Отправлено отчётов: {ok_count} из {len(pending)}.")

    crash_reporter.mark_seen(pending)
    return True
