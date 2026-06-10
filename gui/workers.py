"""Background-task primitives for the GUI.

QObject workers run on their own QThread (moved there by MainWindow._start_task)
and communicate with the UI purely through signals. _TaskHandle keeps the
(worker, thread) pair referenced for the whole lifetime of a task so the OS
thread is never garbage-collected while still running.
"""

from PyQt5.QtCore import QObject, QThread, pyqtSignal


class _Worker(QObject):
    """Runs an arbitrary callable off-thread and emits its result."""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.finished.emit(result if isinstance(result, dict) else {'result': result})
        except Exception as e:
            self.error.emit(str(e))


class _SubdomainWorker(QObject):
    row_found = pyqtSignal(dict)
    progress  = pyqtSignal(int, int)
    finished  = pyqtSignal(dict)
    error     = pyqtSignal(str)

    def __init__(self, scanner, domain: str, passive: bool, brute: bool):
        super().__init__()
        self._scanner = scanner
        self._domain  = domain
        self._passive = passive
        self._brute   = brute

    def run(self):
        try:
            result = self._scanner.scan(
                self._domain,
                on_found=lambda entry: self.row_found.emit(entry),
                on_progress=lambda cur, tot: self.progress.emit(cur, tot),
                passive=self._passive,
                brute=self._brute,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class _CloneWorker(QObject):
    """Thread worker for FrontendCloner with real-time log + page progress."""
    log_message = pyqtSignal(str)
    progress    = pyqtSignal(int, int)   # (current_page, total_pages)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, cloner):
        super().__init__()
        self._cloner  = cloner
        self._total   = 0
        self._current = 0

    def run(self):
        try:
            self._cloner.set_progress_callback(self._on_msg)
            result = self._cloner.clone()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

    def _on_msg(self, msg: str):
        self.log_message.emit(msg)
        if 'HTML файлов для обработки:' in msg:
            try:
                self._total = int(msg.split(':')[-1].strip())
                self._current = 0
                self.progress.emit(0, self._total)
            except ValueError:
                pass
        elif 'Локализую:' in msg:
            self._current += 1
            self.progress.emit(self._current, self._total)


class _CaptureWorker(QObject):
    """Thread worker for SiteContentCapture with thread-safe log routing."""
    log_message = pyqtSignal(str)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, capturer):
        super().__init__()
        self._capturer = capturer

    def run(self):
        try:
            self._capturer.set_progress_callback(lambda msg: self.log_message.emit(msg))
            result = self._capturer.run_capture()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class _TaskHandle:
    """Strong-reference holder for one (worker, thread) pair.

    Every background task lives entirely inside one of these. Keeping both the
    QThread *and* its worker referenced here — and releasing them only after
    the OS thread has actually finished (``thread.finished`` → ``deleteLater``)
    — is what prevents the "QThread: Destroyed while thread is still running"
    crash. Each task gets its own handle, so any number can run concurrently
    without one overwriting another's reference.
    """
    __slots__ = ('id', 'worker', 'thread')

    def __init__(self, task_id: int, worker: QObject, thread: QThread):
        self.id = task_id
        self.worker = worker
        self.thread = thread
