"""In-process event bus for real-time event streaming."""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avakill.core.models import AuditEvent

_Callback = Callable[["AuditEvent"], None]


class EventBus:
    """Simple synchronous in-process event bus.

    Thread-safe singleton used by the Guard to broadcast audit events
    to subscribers (CLI dashboard, SSE endpoints, etc.).

    Usage::

        bus = EventBus.get()
        unsub = bus.subscribe(lambda event: print(event))
        bus.emit(event)
        unsub()  # stop receiving events
    """

    _instance: EventBus | None = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._subscribers: list[_Callback] = []
        self._lock = threading.Lock()

    @classmethod
    def get(cls) -> EventBus:
        """Return the singleton EventBus instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (useful for testing)."""
        with cls._instance_lock:
            cls._instance = None

    def subscribe(self, callback: _Callback) -> Callable[[], None]:
        """Subscribe to events.

        Args:
            callback: Function called with each emitted AuditEvent.

        Returns:
            An unsubscribe function that removes the subscription.
        """
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock, contextlib.suppress(ValueError):
                self._subscribers.remove(callback)

        return unsubscribe

    def emit(self, event: AuditEvent) -> None:
        """Emit an event to all subscribers.

        Exceptions in individual callbacks are silently caught so one
        failing subscriber cannot break the evaluation pipeline.

        Args:
            event: The audit event to broadcast.
        """
        with self._lock:
            subscribers = list(self._subscribers)
        for cb in subscribers:
            with contextlib.suppress(Exception):
                cb(event)
