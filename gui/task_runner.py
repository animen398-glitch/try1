"""gui/task_runner.py

The background-task runner: one place that owns the QThread lifecycle and the
Signals/Slots wiring that decouples the GUI from its workers. Folded into
MainWindow as a mixin, so every tab launches work through ``self._start_task``
(or the ``self._run_async`` convenience) without ever touching threading
plumbing.

The host window is expected to provide a few attributes the runner reads:
  • ``self._tasks``        dict[int, _TaskHandle] — the live-task registry
  • ``self._next_task_id`` int — monotonic id source
  • ``self.task_indicator`` QLabel — "active tasks" status-bar label
  • ``self._set_busy(bool)`` — busy-state toggle (used by _run_async's error path)
"""

from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import QMessageBox

from gui.workers import _TaskHandle, _Worker


class TaskRunnerMixin:
    """QThread lifecycle + concurrency bookkeeping for MainWindow.

    Every background job — generic _Worker, capture, subdomain, clone — is
    launched through _start_task. It owns the full QThread lifecycle and the
    Signals/Slots wiring that decouples the GUI from the worker, so call sites
    only describe *what* to run and *how* to react, never the plumbing.
    """

    def _start_task(self, worker, *, on_finished=None, on_error=None,
                    signals=None) -> int:
        """Run ``worker`` on its own QThread with safe, centralised teardown.

        ``worker`` must expose a ``run()`` slot plus ``finished`` and ``error``
        signals. Cross-thread coupling is pure Signals/Slots:

          • ``on_finished(payload)`` — slot for the worker's ``finished`` signal.
          • ``on_error(message)``    — slot for the worker's ``error`` signal.
          • ``signals``              — iterable of ``(signal, slot)`` pairs for
                                       any extra worker signals (log, progress,
                                       row_found, …).

        The (worker, thread) pair is held in ``self._tasks`` until the OS thread
        has genuinely exited, then both are ``deleteLater``-d and the handle is
        dropped. Returns the task id.
        """
        thread = QThread()
        worker.moveToThread(thread)

        task_id = self._next_task_id
        self._next_task_id += 1
        self._tasks[task_id] = _TaskHandle(task_id, worker, thread)
        self._update_task_indicator()

        thread.started.connect(worker.run)

        # Caller-supplied reactions (queued across the thread boundary).
        if on_finished is not None:
            worker.finished.connect(on_finished)
        if on_error is not None:
            worker.error.connect(on_error)
        for sig, slot in (signals or ()):
            sig.connect(slot)

        # Stop the event loop on either terminal signal …
        worker.finished.connect(thread.quit)
        worker.error.connect(thread.quit)
        # … then tear everything down only after the OS thread has stopped.
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda tid=task_id: (self._tasks.pop(tid, None),
                                 self._update_task_indicator())
        )

        thread.start()
        return task_id

    def _update_task_indicator(self):
        """Reflect the number of live background tasks in the status bar."""
        n = len(self._tasks)
        self.task_indicator.setText(f"⚙ Активных задач: {n}" if n else "")

    def _on_worker_error(self):
        """Re-enable any action buttons that were disabled before a failed task."""
        for attr in ('btn_clone_run', 'dash_scan_btn'):
            btn = getattr(self, attr, None)
            if btn is not None:
                btn.setEnabled(True)

    def _run_async(self, fn, on_done):
        """Convenience wrapper: run ``fn()`` off-thread and deliver its result."""
        self._start_task(
            _Worker(fn),
            on_finished=on_done,
            on_error=lambda e: (
                self._set_busy(False),
                QMessageBox.critical(self, "Ошибка", e),
                self._on_worker_error(),
            ),
        )

    def _await_running_tasks(self, timeout_ms: int = 5000):
        """Block until in-flight worker threads finish.

        Called from MainWindow.closeEvent so no QThread is destroyed mid-run.
        """
        threads = [h.thread for h in list(self._tasks.values())]
        for thread in threads:
            if thread.isRunning():
                thread.quit()
        for thread in threads:
            if thread.isRunning():
                thread.wait(timeout_ms)
