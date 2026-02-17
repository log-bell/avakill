"""SQLite-backed audit logger implementation."""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from agentguard.core.models import AuditEvent, Decision, ToolCall
from agentguard.logging.base import AuditLogger

_BATCH_SIZE = 50
_FLUSH_INTERVAL_S = 0.1  # 100ms

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT,
    agent_id TEXT,
    tool_name TEXT NOT NULL,
    tool_args TEXT,
    decision_allowed INTEGER NOT NULL,
    decision_action TEXT NOT NULL,
    decision_policy TEXT,
    decision_reason TEXT,
    decision_latency_ms REAL,
    execution_result TEXT,
    error TEXT,
    metadata TEXT
)"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_tool_name ON events(tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_decision ON events(decision_allowed)",
    "CREATE INDEX IF NOT EXISTS idx_session ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_agent ON events(agent_id)",
]


def _event_to_row(event: AuditEvent) -> tuple:
    """Flatten an AuditEvent into a row tuple for INSERT."""
    tc = event.tool_call
    d = event.decision
    return (
        event.id,
        tc.timestamp.isoformat(),
        tc.session_id,
        tc.agent_id,
        tc.tool_name,
        json.dumps(tc.arguments),
        int(d.allowed),
        d.action,
        d.policy_name,
        d.reason,
        d.latency_ms,
        json.dumps(event.execution_result) if event.execution_result is not None else None,
        event.error,
        json.dumps(tc.metadata) if tc.metadata else None,
    )


def _row_to_event(row: tuple[Any, ...]) -> AuditEvent:
    """Reconstruct an AuditEvent from a database row."""
    (
        id_,
        timestamp,
        session_id,
        agent_id,
        tool_name,
        tool_args,
        decision_allowed,
        decision_action,
        decision_policy,
        decision_reason,
        decision_latency_ms,
        execution_result,
        error,
        metadata,
    ) = row

    tool_call = ToolCall(
        tool_name=tool_name,
        arguments=json.loads(tool_args) if tool_args else {},
        agent_id=agent_id,
        session_id=session_id,
        timestamp=datetime.fromisoformat(timestamp),
        metadata=json.loads(metadata) if metadata else {},
    )
    decision = Decision(
        allowed=bool(decision_allowed),
        action=decision_action,
        policy_name=decision_policy,
        reason=decision_reason,
        latency_ms=decision_latency_ms or 0.0,
    )
    return AuditEvent(
        id=id_,
        tool_call=tool_call,
        decision=decision,
        execution_result=json.loads(execution_result) if execution_result else None,
        error=error,
    )


def _build_where(
    filters: dict | None,
) -> tuple[str, list[Any]]:
    """Build a WHERE clause and parameter list from a filter dict.

    Supported filter keys:
        tool_name       – exact match or glob pattern (contains ``*``)
        decision_allowed – bool
        agent_id        – exact match
        session_id      – exact match
        time_after      – datetime (inclusive)
        time_before     – datetime (exclusive)
    """
    if not filters:
        return "", []

    clauses: list[str] = []
    params: list[Any] = []

    if "tool_name" in filters:
        tn = filters["tool_name"]
        if "*" in tn:
            # Translate glob to SQL LIKE
            like_pat = tn.replace("*", "%")
            clauses.append("tool_name LIKE ?")
            params.append(like_pat)
        else:
            clauses.append("tool_name = ?")
            params.append(tn)

    if "decision_allowed" in filters:
        clauses.append("decision_allowed = ?")
        params.append(int(filters["decision_allowed"]))

    if "agent_id" in filters:
        clauses.append("agent_id = ?")
        params.append(filters["agent_id"])

    if "session_id" in filters:
        clauses.append("session_id = ?")
        params.append(filters["session_id"])

    if "time_after" in filters:
        clauses.append("timestamp >= ?")
        params.append(filters["time_after"].isoformat())

    if "time_before" in filters:
        clauses.append("timestamp < ?")
        params.append(filters["time_before"].isoformat())

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params


class SQLiteLogger(AuditLogger):
    """SQLite-backed audit logger with batched writes.

    Uses WAL mode for concurrent read/write performance and batches
    inserts (up to 50 events or 100ms, whichever comes first).

    Usage::

        async with SQLiteLogger("/tmp/audit.db") as logger:
            await logger.log(event)
            events = await logger.query({"tool_name": "file_*"})
    """

    def __init__(self, db_path: str | Path = "~/.agentguard/audit.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db: aiosqlite.Connection | None = None
        self._initialised = False
        self._buffer: list[AuditEvent] = []
        self._buffer_lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None  # type: ignore[type-arg]

    async def _ensure_db(self) -> aiosqlite.Connection:
        """Open the connection and create the schema if needed."""
        if self._db is not None and self._initialised:
            return self._db

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        self._db.row_factory = aiosqlite.Row  # type: ignore[assignment]
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute(_CREATE_TABLE)
        for idx_sql in _CREATE_INDEXES:
            await self._db.execute(idx_sql)
        await self._db.commit()
        self._initialised = True
        return self._db

    # ------------------------------------------------------------------
    # Batch buffer management
    # ------------------------------------------------------------------

    def _schedule_flush(self) -> None:
        """Schedule a timed flush if one is not already pending."""
        if self._flush_task is None or self._flush_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._flush_task = loop.create_task(self._timed_flush())
            except RuntimeError:
                pass

    async def _timed_flush(self) -> None:
        """Wait for the flush interval, then flush."""
        await asyncio.sleep(_FLUSH_INTERVAL_S)
        await self.flush()

    async def flush(self) -> None:
        """Force-flush the batch buffer to the database."""
        async with self._buffer_lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()

        db = await self._ensure_db()
        await db.executemany(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [_event_to_row(e) for e in batch],
        )
        await db.commit()

    # ------------------------------------------------------------------
    # AuditLogger interface
    # ------------------------------------------------------------------

    async def log(self, event: AuditEvent) -> None:
        """Add an event to the batch buffer; auto-flush when full."""
        async with self._buffer_lock:
            self._buffer.append(event)
            should_flush = len(self._buffer) >= _BATCH_SIZE

        if should_flush:
            await self.flush()
        else:
            self._schedule_flush()

    async def query(
        self,
        filters: dict | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        await self.flush()
        db = await self._ensure_db()
        where, params = _build_where(filters)
        sql = (
            "SELECT id, timestamp, session_id, agent_id, tool_name, tool_args, "
            "decision_allowed, decision_action, decision_policy, decision_reason, "
            "decision_latency_ms, execution_result, error, metadata "
            f"FROM events{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        cursor = await db.execute(sql, params)
        rows = await cursor.fetchall()
        return [_row_to_event(tuple(r)) for r in rows]

    async def count(self, filters: dict | None = None) -> int:
        await self.flush()
        db = await self._ensure_db()
        where, params = _build_where(filters)
        cursor = await db.execute(f"SELECT COUNT(*) FROM events{where}", params)
        row = await cursor.fetchone()
        return int(row[0])  # type: ignore[index]

    async def stats(self) -> dict:
        await self.flush()
        db = await self._ensure_db()

        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        one_day_ago = (now - timedelta(hours=24)).isoformat()

        cur = await db.execute("SELECT COUNT(*) FROM events")
        total = (await cur.fetchone())[0]  # type: ignore[index]

        cur = await db.execute("SELECT COUNT(*) FROM events WHERE decision_allowed = 1")
        allowed = (await cur.fetchone())[0]  # type: ignore[index]

        denied = total - allowed

        cur = await db.execute("SELECT COUNT(DISTINCT tool_name) FROM events")
        unique_tools = (await cur.fetchone())[0]  # type: ignore[index]

        cur = await db.execute(
            "SELECT COUNT(DISTINCT agent_id) FROM events WHERE agent_id IS NOT NULL"
        )
        unique_agents = (await cur.fetchone())[0]  # type: ignore[index]

        cur = await db.execute(
            "SELECT tool_name, COUNT(*) AS cnt FROM events "
            "WHERE decision_allowed = 0 GROUP BY tool_name ORDER BY cnt DESC LIMIT 10"
        )
        top_denied = [(r[0], r[1]) for r in await cur.fetchall()]

        cur = await db.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (one_hour_ago,))
        last_hour = (await cur.fetchone())[0]  # type: ignore[index]

        cur = await db.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ?", (one_day_ago,))
        last_24h = (await cur.fetchone())[0]  # type: ignore[index]

        return {
            "total_events": total,
            "allowed": allowed,
            "denied": denied,
            "denial_rate": round((denied / total * 100) if total else 0.0, 2),
            "unique_tools": unique_tools,
            "unique_agents": unique_agents,
            "top_denied_tools": top_denied,
            "events_last_hour": last_hour,
            "events_last_24h": last_24h,
        }

    async def close(self) -> None:
        """Flush remaining events and close the connection."""
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
        await self.flush()
        if self._db is not None:
            await self._db.close()
            self._db = None
            self._initialised = False

    async def __aenter__(self) -> SQLiteLogger:
        await self._ensure_db()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


class SyncSQLiteLogger:
    """Synchronous wrapper around :class:`SQLiteLogger`.

    Runs each async call in a dedicated event loop on a background thread
    so it can be used from synchronous code without an existing loop.

    Usage::

        with SyncSQLiteLogger("/tmp/audit.db") as logger:
            logger.log(event)
            events = logger.query({"tool_name": "file_*"})
    """

    def __init__(self, db_path: str | Path = "~/.agentguard/audit.db") -> None:
        self._inner = SQLiteLogger(db_path)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def _run(self, coro: Any) -> Any:
        """Submit a coroutine to the background loop and block for its result."""
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def log(self, event: AuditEvent) -> None:
        self._run(self._inner.log(event))

    def query(
        self,
        filters: dict | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        result: list[AuditEvent] = self._run(self._inner.query(filters, limit, offset))
        return result

    def count(self, filters: dict | None = None) -> int:
        result: int = self._run(self._inner.count(filters))
        return result

    def stats(self) -> dict:
        result: dict = self._run(self._inner.stats())  # type: ignore[type-arg]
        return result

    def flush(self) -> None:
        self._run(self._inner.flush())

    def close(self) -> None:
        self._run(self._inner.close())
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop.close()

    def __enter__(self) -> SyncSQLiteLogger:
        self._run(self._inner._ensure_db())
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def get_default_logger(path: str | None = None) -> SQLiteLogger:
    """Get or create the default SQLite logger.

    Args:
        path: Optional override for the database path.
            Defaults to ``~/.agentguard/audit.db``.

    Returns:
        A new :class:`SQLiteLogger` instance.
    """
    return SQLiteLogger(path or "~/.agentguard/audit.db")
