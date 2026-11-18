"""
AegisX — background task framework.

All long-running operations (provider lookups, source tests, report
generation, imports) execute on a QThreadPool so the GUI never blocks.
``TaskManager`` is a QObject living on the main thread; worker results are
marshalled back through queued signals, so ``on_done``/``on_error`` handlers
always run on the GUI thread and may safely touch widgets.
"""

from __future__ import annotations

import itertools
import logging
import traceback
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

log = logging.getLogger("aegisx.workers")


class _WorkerSignals(QObject):
    done = Signal(str, object)      # task_id, result
    failed = Signal(str, str)       # task_id, error message


class Worker(QRunnable):
    def __init__(self, task_id: str, fn: Callable, *args, **kwargs) -> None:
        super().__init__()
        self.task_id = task_id
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = _WorkerSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:  # runs on a worker thread
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as e:  # noqa: BLE001
            log.error("Task %s failed: %s\n%s", self.task_id, e, traceback.format_exc())
            self.signals.failed.emit(self.task_id, f"{type(e).__name__}: {e}")
            return
        self.signals.done.emit(self.task_id, result)


class TaskManager(QObject):
    """Application-wide task scheduler (singleton)."""

    _instance: "TaskManager | None" = None
    _counter = itertools.count(1)

    _deliver_done = Signal(object, object)   # (handler, result)
    _deliver_error = Signal(object, str)     # (handler, error)

    def __init__(self) -> None:
        super().__init__()
        self._pool = QThreadPool.globalInstance()
        self._pool.setMaxThreadCount(8)
        self._active = 0
        self._pending: dict[str, tuple[Callable | None, Callable | None]] = {}
        # QObject-receiver connections -> safe queued delivery to main thread
        self._deliver_done.connect(self._on_deliver_done)
        self._deliver_error.connect(self._on_deliver_error)
        TaskManager._instance = self

    @classmethod
    def get(cls) -> "TaskManager":
        if cls._instance is None:
            cls._instance = TaskManager()
        return cls._instance

    # ------------------------------------------------------------ delivery
    def _on_deliver_done(self, handler: object, result: object) -> None:
        self._active = max(0, self._active - 1)
        if handler:
            try:
                handler(result)  # type: ignore[operator]
            except Exception:  # noqa: BLE001
                log.exception("on_done handler failed")

    def _on_deliver_error(self, handler: object, err: str) -> None:
        self._active = max(0, self._active - 1)
        if handler:
            try:
                handler(err)  # type: ignore[operator]
            except Exception:  # noqa: BLE001
                log.exception("on_error handler failed")

    # ----------------------------------------------------- worker callbacks
    def _worker_done(self, task_id: str, result: object) -> None:
        callbacks = self._pending.pop(task_id, (None, None))
        self._deliver_done.emit(callbacks[0], result)

    def _worker_failed(self, task_id: str, err: str) -> None:
        callbacks = self._pending.pop(task_id, (None, None))
        self._deliver_error.emit(callbacks[1], err)

    # ------------------------------------------------------------------ api
    def submit(self, fn: Callable, *args, description: str = "",
               on_done: Callable | None = None, on_error: Callable | None = None,
               **kwargs) -> str:
        task_id = f"task-{next(self._counter)}"
        self._pending[task_id] = (on_done, on_error)
        self._active += 1
        worker = Worker(task_id, fn, *args, **kwargs)
        worker.signals.done.connect(self._worker_done)
        worker.signals.failed.connect(self._worker_failed)
        self._pool.start(worker)
        if description:
            log.debug("Task submitted: %s", description)
        return task_id

    def active_count(self) -> int:
        return self._active

    def wait_for_shutdown(self, msecs: int = 3000) -> None:
        self._pool.waitForDone(msecs)
