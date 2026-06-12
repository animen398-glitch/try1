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
    row_found   = pyqtSignal(dict)
    row_updated = pyqtSignal(dict)   # active-check enrichment for an existing row
    progress    = pyqtSignal(int, int)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, scanner, domain: str, passive: bool, brute: bool,
                 active: bool = False, amass: bool = False):
        super().__init__()
        self._scanner = scanner
        self._domain  = domain
        self._passive = passive
        self._brute   = brute
        self._active  = active
        self._amass   = amass

    def run(self):
        try:
            result = self._scanner.scan(
                self._domain,
                on_found=lambda entry: self.row_found.emit(entry),
                on_progress=lambda cur, tot: self.progress.emit(cur, tot),
                on_update=lambda entry: self.row_updated.emit(entry),
                passive=self._passive,
                brute=self._brute,
                active=self._active,
                amass=self._amass,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class _CloneWorker(QObject):
    """Thread worker for FrontendCloner: forwards log text + structured
    page progress straight from the engine's callbacks to Qt signals."""
    log_message = pyqtSignal(str)
    progress    = pyqtSignal(int, int)   # (current_page, total_pages)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, cloner):
        super().__init__()
        self._cloner = cloner

    def run(self):
        try:
            self._cloner.set_progress_callback(self.log_message.emit)
            self._cloner.set_page_progress_callback(self.progress.emit)
            result = self._cloner.clone()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


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


class _CollectionWorker(QObject):
    """Thread worker for CollectionRunner (Full Collection) with log routing."""
    log_message = pyqtSignal(str)
    finished    = pyqtSignal(dict)
    error       = pyqtSignal(str)

    def __init__(self, runner, url: str, output_base: str):
        super().__init__()
        self._runner = runner
        self._url = url
        self._output_base = output_base

    def run(self):
        try:
            self._runner.set_progress_callback(lambda msg: self.log_message.emit(msg))
            result = self._runner.run(self._url, self._output_base)
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
