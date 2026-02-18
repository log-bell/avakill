"""Tests for the audit analytics engine."""

from __future__ import annotations

from pathlib import Path

from avakill.analytics.engine import AuditAnalytics
from avakill.core.models import AuditEvent, Decision, ToolCall
from avakill.logging.sqlite_logger import SQLiteLogger


def _make_event(
    tool: str = "file_read",
    allowed: bool = True,
    agent_id: str | None = "agent-1",
    policy_name: str | None = "allow-read",
) -> AuditEvent:
    action = "allow" if allowed else "deny"
    return AuditEvent(
        tool_call=ToolCall(
            tool_name=tool,
            arguments={},
            agent_id=agent_id,
        ),
        decision=Decision(
            allowed=allowed,
            action=action,
            policy_name=policy_name,
        ),
    )


async def _seed_logger(logger: SQLiteLogger) -> None:
    """Insert a mix of events for analytics tests."""
    events = [
        # agent-1: 3 allowed reads, 1 denied write
        _make_event("file_read", allowed=True, agent_id="agent-1", policy_name="allow-read"),
        _make_event("file_read", allowed=True, agent_id="agent-1", policy_name="allow-read"),
        _make_event("file_read", allowed=True, agent_id="agent-1", policy_name="allow-read"),
        _make_event("file_write", allowed=False, agent_id="agent-1", policy_name="deny-write"),
        # agent-2: 2 denied deletes
        _make_event("file_delete", allowed=False, agent_id="agent-2", policy_name="deny-delete"),
        _make_event("file_delete", allowed=False, agent_id="agent-2", policy_name="deny-delete"),
        # agent-3: 1 allowed search
        _make_event("web_search", allowed=True, agent_id="agent-3", policy_name="allow-search"),
    ]
    for event in events:
        await logger.log(event)
    await logger.flush()


class TestAuditAnalytics:
    """Tests for AuditAnalytics."""

    async def test_denial_trend(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        async with SQLiteLogger(db) as logger:
            await _seed_logger(logger)
            analytics = AuditAnalytics(logger)
            trend = await analytics.denial_trend(hours=24, bucket_minutes=60)
            # We have 3 denials total, so the trend should have at least 1 bucket
            assert isinstance(trend, list)
            total_denials = sum(b["count"] for b in trend)
            assert total_denials == 3

    async def test_tool_usage_summary(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        async with SQLiteLogger(db) as logger:
            await _seed_logger(logger)
            analytics = AuditAnalytics(logger)
            summary = await analytics.tool_usage_summary()
            assert "file_read" in summary
            assert summary["file_read"]["allowed"] == 3
            assert summary["file_read"]["denied"] == 0
            assert "file_write" in summary
            assert summary["file_write"]["denied"] == 1
            assert "file_delete" in summary
            assert summary["file_delete"]["denied"] == 2

    async def test_agent_risk_scores(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        async with SQLiteLogger(db) as logger:
            await _seed_logger(logger)
            analytics = AuditAnalytics(logger)
            scores = await analytics.agent_risk_scores()
            # agent-1: 1 denied / 4 total = 0.25
            assert scores["agent-1"] == 0.25
            # agent-2: 2 denied / 2 total = 1.0
            assert scores["agent-2"] == 1.0
            # agent-3: 0 denied / 1 total = 0.0
            assert scores["agent-3"] == 0.0

    async def test_policy_effectiveness(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        async with SQLiteLogger(db) as logger:
            await _seed_logger(logger)
            analytics = AuditAnalytics(logger)
            eff = await analytics.policy_effectiveness()
            assert "allow-read" in eff
            assert eff["allow-read"]["matches"] == 3
            assert eff["allow-read"]["allows"] == 3
            assert eff["allow-read"]["denials"] == 0
            assert "deny-write" in eff
            assert eff["deny-write"]["denials"] == 1
            assert "deny-delete" in eff
            assert eff["deny-delete"]["matches"] == 2

    async def test_empty_db_returns_empty_results(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        async with SQLiteLogger(db) as logger:
            analytics = AuditAnalytics(logger)
            trend = await analytics.denial_trend()
            assert trend == []
            summary = await analytics.tool_usage_summary()
            assert summary == {}
            scores = await analytics.agent_risk_scores()
            assert scores == {}
            eff = await analytics.policy_effectiveness()
            assert eff == {}
