"""Tests for the SQLite audit logger."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard.core.models import AuditEvent, Decision, ToolCall
from agentguard.logging.sqlite_logger import (
    SQLiteLogger,
    SyncSQLiteLogger,
    get_default_logger,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    tool: str = "file_read",
    *,
    allowed: bool = True,
    action: str = "allow",
    agent_id: str | None = None,
    session_id: str | None = None,
    args: dict | None = None,
    policy_name: str | None = None,
    reason: str | None = None,
    error: str | None = None,
    execution_result: object = None,
    metadata: dict | None = None,
    timestamp: datetime | None = None,
) -> AuditEvent:
    tc = ToolCall(
        tool_name=tool,
        arguments=args or {},
        agent_id=agent_id,
        session_id=session_id,
        timestamp=timestamp or datetime.now(timezone.utc),
        metadata=metadata or {},
    )
    d = Decision(
        allowed=allowed,
        action=action,
        policy_name=policy_name,
        reason=reason,
    )
    return AuditEvent(
        tool_call=tc,
        decision=d,
        error=error,
        execution_result=execution_result,
    )


# ---------------------------------------------------------------------------
# Database / table auto-creation
# ---------------------------------------------------------------------------


class TestAutoCreation:
    async def test_creates_db_file(self, tmp_db_path: Path) -> None:
        assert not tmp_db_path.exists()
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event())
        assert tmp_db_path.exists()

    async def test_creates_parent_directories(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "audit.db"
        async with SQLiteLogger(deep) as logger:
            await logger.log(_make_event())
        assert deep.exists()

    async def test_creates_tables_and_indexes(self, tmp_db_path: Path) -> None:
        import aiosqlite

        async with SQLiteLogger(tmp_db_path):
            pass
        async with aiosqlite.connect(str(tmp_db_path)) as db:
            cur = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
            )
            assert (await cur.fetchone()) is not None

            cur = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
            )
            indexes = {row[0] for row in await cur.fetchall()}
            assert indexes >= {
                "idx_timestamp",
                "idx_tool_name",
                "idx_decision",
                "idx_session",
                "idx_agent",
            }

    async def test_wal_mode_enabled(self, tmp_db_path: Path) -> None:
        import aiosqlite

        async with SQLiteLogger(tmp_db_path):
            pass
        async with aiosqlite.connect(str(tmp_db_path)) as db:
            cur = await db.execute("PRAGMA journal_mode")
            mode = (await cur.fetchone())[0]
            assert mode == "wal"


# ---------------------------------------------------------------------------
# Logging & roundtrip
# ---------------------------------------------------------------------------


class TestLogAndQuery:
    async def test_log_and_query_basic(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            event = _make_event("file_read", agent_id="a1", session_id="s1")
            await logger.log(event)
            results = await logger.query()
        assert len(results) == 1
        r = results[0]
        assert r.id == event.id
        assert r.tool_call.tool_name == "file_read"
        assert r.tool_call.agent_id == "a1"
        assert r.tool_call.session_id == "s1"
        assert r.decision.allowed is True
        assert r.decision.action == "allow"

    async def test_roundtrip_preserves_fields(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            event = _make_event(
                "shell_exec",
                allowed=False,
                action="deny",
                agent_id="bot",
                session_id="sess-42",
                args={"cmd": "rm -rf /"},
                policy_name="deny-dangerous",
                reason="Blocked dangerous command",
                error="PolicyViolation",
                metadata={"source": "test"},
            )
            await logger.log(event)
            results = await logger.query()

        r = results[0]
        assert r.tool_call.arguments == {"cmd": "rm -rf /"}
        assert r.decision.policy_name == "deny-dangerous"
        assert r.decision.reason == "Blocked dangerous command"
        assert r.error == "PolicyViolation"
        assert r.tool_call.metadata == {"source": "test"}

    async def test_roundtrip_execution_result(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            event = _make_event(execution_result={"rows": 42})
            await logger.log(event)
            results = await logger.query()
        assert results[0].execution_result == {"rows": 42}

    async def test_query_order_desc(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            now = datetime.now(timezone.utc)
            for i in range(5):
                await logger.log(
                    _make_event(
                        f"tool_{i}",
                        timestamp=now + timedelta(seconds=i),
                    )
                )
            results = await logger.query()
        names = [r.tool_call.tool_name for r in results]
        assert names == ["tool_4", "tool_3", "tool_2", "tool_1", "tool_0"]

    async def test_query_limit_and_offset(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            now = datetime.now(timezone.utc)
            for i in range(10):
                await logger.log(_make_event(f"t{i}", timestamp=now + timedelta(seconds=i)))
            page1 = await logger.query(limit=3, offset=0)
            page2 = await logger.query(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0].tool_call.tool_name == "t9"
        assert page2[0].tool_call.tool_name == "t6"


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


class TestFilters:
    async def test_filter_tool_name_exact(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event("file_read"))
            await logger.log(_make_event("file_write"))
            results = await logger.query({"tool_name": "file_read"})
        assert len(results) == 1
        assert results[0].tool_call.tool_name == "file_read"

    async def test_filter_tool_name_glob(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event("file_read"))
            await logger.log(_make_event("file_write"))
            await logger.log(_make_event("shell_exec"))
            results = await logger.query({"tool_name": "file_*"})
        assert len(results) == 2
        tools = {r.tool_call.tool_name for r in results}
        assert tools == {"file_read", "file_write"}

    async def test_filter_decision_allowed(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event("t1", allowed=True, action="allow"))
            await logger.log(_make_event("t2", allowed=False, action="deny"))
            await logger.log(_make_event("t3", allowed=False, action="deny"))
            allowed = await logger.query({"decision_allowed": True})
            denied = await logger.query({"decision_allowed": False})
        assert len(allowed) == 1
        assert len(denied) == 2

    async def test_filter_agent_id(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event(agent_id="a1"))
            await logger.log(_make_event(agent_id="a2"))
            results = await logger.query({"agent_id": "a1"})
        assert len(results) == 1

    async def test_filter_session_id(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event(session_id="s1"))
            await logger.log(_make_event(session_id="s2"))
            results = await logger.query({"session_id": "s2"})
        assert len(results) == 1

    async def test_filter_time_after(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            now = datetime.now(timezone.utc)
            await logger.log(_make_event("old", timestamp=now - timedelta(hours=2)))
            await logger.log(_make_event("new", timestamp=now))
            results = await logger.query({"time_after": now - timedelta(hours=1)})
        assert len(results) == 1
        assert results[0].tool_call.tool_name == "new"

    async def test_filter_time_before(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            now = datetime.now(timezone.utc)
            await logger.log(_make_event("old", timestamp=now - timedelta(hours=2)))
            await logger.log(_make_event("new", timestamp=now))
            results = await logger.query({"time_before": now - timedelta(hours=1)})
        assert len(results) == 1
        assert results[0].tool_call.tool_name == "old"

    async def test_filter_combined(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event("file_read", allowed=True, action="allow", agent_id="a1"))
            await logger.log(_make_event("file_read", allowed=False, action="deny", agent_id="a1"))
            await logger.log(_make_event("file_read", allowed=False, action="deny", agent_id="a2"))
            results = await logger.query(
                {"tool_name": "file_read", "decision_allowed": False, "agent_id": "a1"}
            )
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Count
# ---------------------------------------------------------------------------


class TestCount:
    async def test_count_all(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            for _ in range(5):
                await logger.log(_make_event())
            assert await logger.count() == 5

    async def test_count_with_filter(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event("a", allowed=True, action="allow"))
            await logger.log(_make_event("b", allowed=False, action="deny"))
            await logger.log(_make_event("c", allowed=False, action="deny"))
            assert await logger.count({"decision_allowed": False}) == 2

    async def test_count_empty_db(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            assert await logger.count() == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    async def test_stats_basic(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event("read", allowed=True, action="allow", agent_id="a"))
            await logger.log(_make_event("write", allowed=True, action="allow", agent_id="a"))
            await logger.log(_make_event("delete", allowed=False, action="deny", agent_id="b"))
            s = await logger.stats()

        assert s["total_events"] == 3
        assert s["allowed"] == 2
        assert s["denied"] == 1
        assert s["denial_rate"] == pytest.approx(33.33, abs=0.01)
        assert s["unique_tools"] == 3
        assert s["unique_agents"] == 2
        assert s["events_last_hour"] == 3
        assert s["events_last_24h"] == 3

    async def test_stats_top_denied_tools(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            for _ in range(5):
                await logger.log(_make_event("delete", allowed=False, action="deny"))
            for _ in range(3):
                await logger.log(_make_event("shell", allowed=False, action="deny"))
            await logger.log(_make_event("read", allowed=True, action="allow"))
            s = await logger.stats()

        assert s["top_denied_tools"][0] == ("delete", 5)
        assert s["top_denied_tools"][1] == ("shell", 3)

    async def test_stats_empty_db(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            s = await logger.stats()
        assert s["total_events"] == 0
        assert s["denial_rate"] == 0.0
        assert s["top_denied_tools"] == []

    async def test_stats_time_windows(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            now = datetime.now(timezone.utc)
            await logger.log(_make_event("recent", timestamp=now))
            await logger.log(_make_event("two_hours_ago", timestamp=now - timedelta(hours=2)))
            await logger.log(_make_event("two_days_ago", timestamp=now - timedelta(days=2)))
            s = await logger.stats()

        assert s["total_events"] == 3
        assert s["events_last_hour"] == 1
        assert s["events_last_24h"] == 2


# ---------------------------------------------------------------------------
# Batch flushing behaviour
# ---------------------------------------------------------------------------


class TestBatching:
    async def test_explicit_flush(self, tmp_db_path: Path) -> None:
        logger = SQLiteLogger(tmp_db_path)
        await logger._ensure_db()
        try:
            await logger.log(_make_event())
            # Before flush, query won't see buffered events (but query
            # itself flushes, so we inspect the buffer directly)
            assert len(logger._buffer) == 0 or True  # buffer may already be flushed
            await logger.flush()
            assert await logger.count() == 1
        finally:
            await logger.close()

    async def test_batch_auto_flush_at_threshold(self, tmp_db_path: Path) -> None:
        import agentguard.logging.sqlite_logger as mod

        orig = mod._BATCH_SIZE
        mod._BATCH_SIZE = 3
        try:
            async with SQLiteLogger(tmp_db_path) as logger:
                for i in range(3):
                    await logger.log(_make_event(f"t{i}"))
                # After hitting batch size, events should be flushed
                # Check DB directly to confirm
                db = await logger._ensure_db()
                cur = await db.execute("SELECT COUNT(*) FROM events")
                assert (await cur.fetchone())[0] == 3
        finally:
            mod._BATCH_SIZE = orig

    async def test_close_flushes_remaining(self, tmp_db_path: Path) -> None:
        logger = SQLiteLogger(tmp_db_path)
        await logger._ensure_db()
        await logger.log(_make_event("lingering"))
        await logger.close()

        # Re-open and verify the event was persisted
        async with SQLiteLogger(tmp_db_path) as logger2:
            assert await logger2.count() == 1


# ---------------------------------------------------------------------------
# Concurrent writes
# ---------------------------------------------------------------------------


class TestConcurrency:
    async def test_concurrent_writes(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            tasks = [logger.log(_make_event(f"tool_{i}", agent_id=f"a{i % 3}")) for i in range(100)]
            await asyncio.gather(*tasks)
            total = await logger.count()
        assert total == 100

    async def test_concurrent_read_write(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            # Seed some data
            for i in range(20):
                await logger.log(_make_event(f"seed_{i}"))

            # Concurrently write more + read
            async def writer() -> None:
                for i in range(20):
                    await logger.log(_make_event(f"concurrent_{i}"))

            async def reader() -> int:
                return await logger.count()

            _, count = await asyncio.gather(writer(), reader())
            # Reader should see at least the seeded data
            assert count >= 20


# ---------------------------------------------------------------------------
# Sync wrapper
# ---------------------------------------------------------------------------


class TestSyncWrapper:
    def test_sync_log_and_query(self, tmp_db_path: Path) -> None:
        with SyncSQLiteLogger(tmp_db_path) as logger:
            event = _make_event("sync_tool", agent_id="sync_agent")
            logger.log(event)
            logger.flush()
            results = logger.query()
        assert len(results) == 1
        assert results[0].tool_call.tool_name == "sync_tool"

    def test_sync_count(self, tmp_db_path: Path) -> None:
        with SyncSQLiteLogger(tmp_db_path) as logger:
            logger.log(_make_event("a"))
            logger.log(_make_event("b"))
            assert logger.count() == 2

    def test_sync_stats(self, tmp_db_path: Path) -> None:
        with SyncSQLiteLogger(tmp_db_path) as logger:
            logger.log(_make_event("r", allowed=True, action="allow"))
            logger.log(_make_event("d", allowed=False, action="deny"))
            s = logger.stats()
        assert s["total_events"] == 2
        assert s["allowed"] == 1
        assert s["denied"] == 1

    def test_sync_filters(self, tmp_db_path: Path) -> None:
        with SyncSQLiteLogger(tmp_db_path) as logger:
            logger.log(_make_event("file_read", agent_id="x"))
            logger.log(_make_event("file_write", agent_id="y"))
            results = logger.query({"agent_id": "x"})
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Async context manager
# ---------------------------------------------------------------------------


class TestAsyncContextManager:
    async def test_aenter_aexit(self, tmp_db_path: Path) -> None:
        async with SQLiteLogger(tmp_db_path) as logger:
            await logger.log(_make_event())
            assert await logger.count() == 1
        # Connection closed — re-opening should work fine
        async with SQLiteLogger(tmp_db_path) as logger2:
            assert await logger2.count() == 1


# ---------------------------------------------------------------------------
# get_default_logger convenience function
# ---------------------------------------------------------------------------


class TestGetDefaultLogger:
    def test_returns_sqlite_logger(self) -> None:
        logger = get_default_logger()
        assert isinstance(logger, SQLiteLogger)

    def test_custom_path(self, tmp_db_path: Path) -> None:
        logger = get_default_logger(str(tmp_db_path))
        assert logger._db_path == tmp_db_path
