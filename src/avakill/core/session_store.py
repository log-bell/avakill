"""Bounded session state for cross-call correlation (T4).

Provides a thread-safe, memory-bounded store that tracks tagged tool calls
per session. Each session uses a ring buffer with configurable max size,
and the store enforces a max session count with LRU eviction and TTL expiry.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TaggedCall:
    """A tool call annotated with behavioral tags.

    Attributes:
        tool_name: The canonical tool name.
        tags: Frozenset of behavioral tags (e.g. ``credential_read``, ``encode``).
        timestamp: Monotonic timestamp when the call was recorded.
    """

    tool_name: str
    tags: frozenset[str]
    timestamp: float


@dataclass
class SessionRing:
    """Ring buffer of TaggedCalls for a single session.

    Attributes:
        max_size: Maximum number of entries before oldest is evicted.
        last_activity: Monotonic timestamp of last record.
    """

    max_size: int = 50
    last_activity: float = field(default_factory=time.monotonic)
    _entries: list[TaggedCall] = field(default_factory=list)

    def append(self, entry: TaggedCall) -> None:
        """Append an entry, evicting the oldest if at capacity."""
        self._entries.append(entry)
        if len(self._entries) > self.max_size:
            self._entries.pop(0)
        self.last_activity = entry.timestamp

    @property
    def entries(self) -> list[TaggedCall]:
        """Return a copy of all entries."""
        return list(self._entries)

    def tag_sequence(self) -> list[frozenset[str]]:
        """Return the sequence of tag sets in order."""
        return [e.tags for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)


class SessionStore:
    """Thread-safe bounded store mapping session IDs to SessionRings.

    Enforces:
    - Max sessions (LRU eviction when exceeded)
    - TTL-based lazy expiry (checked at most once per minute)
    """

    def __init__(
        self,
        max_sessions: int = 200,
        ttl_seconds: float = 3600.0,
        ring_size: int = 50,
    ) -> None:
        self._max_sessions = max_sessions
        self._ttl_seconds = ttl_seconds
        self._ring_size = ring_size
        self._sessions: OrderedDict[str, SessionRing] = OrderedDict()
        self._lock = threading.Lock()
        self._last_eviction: float = 0.0

    def record(self, session_id: str, entry: TaggedCall) -> SessionRing:
        """Record a tagged call for a session, returning the session ring."""
        with self._lock:
            self._maybe_evict_expired()

            if session_id in self._sessions:
                ring = self._sessions[session_id]
                self._sessions.move_to_end(session_id)
            else:
                ring = SessionRing(max_size=self._ring_size)
                self._sessions[session_id] = ring
                # Evict LRU if over capacity
                while len(self._sessions) > self._max_sessions:
                    self._sessions.popitem(last=False)

            ring.append(entry)
            return ring

    def get(self, session_id: str) -> SessionRing | None:
        """Get the session ring for a session, or None if not found."""
        with self._lock:
            ring = self._sessions.get(session_id)
            if ring is not None:
                self._sessions.move_to_end(session_id)
            return ring

    def clear(self) -> None:
        """Remove all sessions (for testing)."""
        with self._lock:
            self._sessions.clear()

    def _maybe_evict_expired(self) -> None:
        """Evict expired sessions, at most once per minute."""
        now = time.monotonic()
        if now - self._last_eviction < 60.0:
            return
        self._last_eviction = now

        expired = [
            sid
            for sid, ring in self._sessions.items()
            if (now - ring.last_activity) > self._ttl_seconds
        ]
        for sid in expired:
            del self._sessions[sid]
