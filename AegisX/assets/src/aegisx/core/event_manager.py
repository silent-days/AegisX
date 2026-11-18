"""
AegisX — application event bus.

Pure-Python publish/subscribe hub (no Qt dependency) with a bounded ring
buffer of recent events. The UI bridges bus traffic onto the main thread.
Every significant platform action (lookups, source changes, reports) is
published here and persisted in the ``events`` table.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

SEVERITIES = ("info", "low", "medium", "high", "critical", "success", "warning")


@dataclass
class Event:
    kind: str          # e.g. "lookup.completed", "source.error", "report.generated"
    message: str
    severity: str = "info"
    data: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class EventManager:
    """Thread-safe in-memory event bus."""

    def __init__(self, history_size: int = 200) -> None:
        self._subs: dict[str, list[Callable[[Event], None]]] = {}
        self._any: list[Callable[[Event], None]] = []
        self._history: deque[Event] = deque(maxlen=history_size)
        self._lock = threading.RLock()

    def subscribe(self, kind: str, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self._subs.setdefault(kind, []).append(callback)

    def subscribe_all(self, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self._any.append(callback)

    def unsubscribe(self, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self._any = [c for c in self._any if c is not callback]
            for kind, cbs in list(self._subs.items()):
                self._subs[kind] = [c for c in cbs if c is not callback]

    def publish(self, kind: str, message: str, severity: str = "info", **data) -> Event:
        if severity not in SEVERITIES:
            severity = "info"
        event = Event(kind=kind, message=message, severity=severity, data=data)
        with self._lock:
            self._history.appendleft(event)
            callbacks = list(self._any) + list(self._subs.get(kind, []))
        for cb in callbacks:
            try:
                cb(event)
            except Exception:  # noqa: BLE001 - subscriber isolation
                pass
        return event

    def recent(self, limit: int = 30) -> list[Event]:
        with self._lock:
            return list(self._history)[:limit]

    def clear(self) -> None:
        with self._lock:
            self._history.clear()
