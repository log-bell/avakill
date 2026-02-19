"""Pluggable rate-limit storage backends for PolicyEngine."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class RateLimitBackend(Protocol):
    """Protocol for rate-limit timestamp storage.

    Implementations must be thread-safe.
    """

    def record(self, tool_name: str, timestamp: float) -> None:
        """Persist a call timestamp for the given tool."""
        ...

    def load(self, tool_name: str, window_seconds: float) -> list[float]:
        """Return all timestamps for *tool_name* within the last *window_seconds*."""
        ...

    def load_all(self, window_seconds: float) -> dict[str, list[float]]:
        """Return all unexpired timestamps grouped by tool name."""
        ...

    def cleanup(self, max_window_seconds: float) -> None:
        """Delete all timestamps older than *max_window_seconds* ago."""
        ...

    def close(self) -> None:
        """Release any held resources."""
        ...


class InMemoryBackend:
    """Default in-memory backend — identical to the original behaviour."""

    def record(self, tool_name: str, timestamp: float) -> None:
        pass  # PolicyEngine manages the in-memory deque directly

    def load(self, tool_name: str, window_seconds: float) -> list[float]:
        return []  # Nothing to restore

    def load_all(self, window_seconds: float) -> dict[str, list[float]]:
        return {}  # Nothing to restore

    def cleanup(self, max_window_seconds: float) -> None:
        pass

    def close(self) -> None:
        pass


_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS rate_limits (
    tool_name TEXT NOT NULL,
    timestamp REAL NOT NULL
)"""

_CREATE_INDEX = "CREATE INDEX IF NOT EXISTS idx_rl_tool_ts ON rate_limits(tool_name, timestamp)"


class SQLiteBackend:
    """SQLite-backed rate-limit storage.

    Uses WAL journal mode for concurrent read/write performance and
    batches writes to minimise I/O.  All public methods are thread-safe.

    Args:
        db_path: Filesystem path for the SQLite database.
            Defaults to ``~/.avakill/ratelimits.db``.
    """

    _BATCH_SIZE = 64

    def __init__(self, db_path: str | Path = "~/.avakill/ratelimits.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._buffer: list[tuple[str, float]] = []
        self._conn: sqlite3.Connection = self._open()

    # -- internal helpers --------------------------------------------------

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(_CREATE_TABLE)
        conn.execute(_CREATE_INDEX)
        conn.commit()
        return conn

    def _flush(self) -> None:
        """Write buffered rows to the database.  Caller must hold *_lock*."""
        if not self._buffer:
            return
        self._conn.executemany(
            "INSERT INTO rate_limits (tool_name, timestamp) VALUES (?, ?)",
            self._buffer,
        )
        self._conn.commit()
        self._buffer.clear()

    # -- public interface --------------------------------------------------

    def record(self, tool_name: str, timestamp: float) -> None:
        with self._lock:
            self._buffer.append((tool_name, timestamp))
            if len(self._buffer) >= self._BATCH_SIZE:
                self._flush()

    def load(self, tool_name: str, window_seconds: float) -> list[float]:
        cutoff = time.time() - window_seconds
        with self._lock:
            # Flush pending writes so the query sees them
            self._flush()
            cursor = self._conn.execute(
                "SELECT timestamp FROM rate_limits "
                "WHERE tool_name = ? AND timestamp > ? ORDER BY timestamp",
                (tool_name, cutoff),
            )
            return [row[0] for row in cursor.fetchall()]

    def load_all(self, window_seconds: float) -> dict[str, list[float]]:
        cutoff = time.time() - window_seconds
        with self._lock:
            self._flush()
            cursor = self._conn.execute(
                "SELECT tool_name, timestamp FROM rate_limits "
                "WHERE timestamp > ? ORDER BY tool_name, timestamp",
                (cutoff,),
            )
            result: dict[str, list[float]] = {}
            for tool_name, ts in cursor.fetchall():
                result.setdefault(tool_name, []).append(ts)
            return result

    def cleanup(self, max_window_seconds: float) -> None:
        cutoff = time.time() - max_window_seconds
        with self._lock:
            self._flush()
            self._conn.execute("DELETE FROM rate_limits WHERE timestamp <= ?", (cutoff,))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._flush()
            self._conn.close()
