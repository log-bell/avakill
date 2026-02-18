"""Tests for the avakill fix CLI command."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli
from avakill.core.models import AuditEvent, Decision, ToolCall
from avakill.logging.sqlite_logger import SQLiteLogger


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def db_with_denials(tmp_path: Path) -> Path:
    """Create a temp DB with denied events of varying types."""
    db_path = tmp_path / "test_audit.db"

    async def _seed():
        logger = SQLiteLogger(str(db_path))
        try:
            await logger._ensure_db()

            # Denied by policy rule
            await logger.log(AuditEvent(
                tool_call=ToolCall(
                    tool_name="file_delete",
                    arguments={"path": "/etc/passwd"},
                    agent_id="claude",
                ),
                decision=Decision(
                    allowed=False,
                    action="deny",
                    policy_name="block-deletes",
                    reason="Matched rule 'block-deletes'",
                ),
            ))
            # Denied by rate limit
            await logger.log(AuditEvent(
                tool_call=ToolCall(
                    tool_name="web_search",
                    arguments={"q": "test"},
                    agent_id="claude",
                ),
                decision=Decision(
                    allowed=False,
                    action="deny",
                    policy_name="rate-limited-search",
                    reason="Rate limit exceeded: 10 calls per 60s",
                ),
            ))
            # Denied by default deny
            await logger.log(AuditEvent(
                tool_call=ToolCall(
                    tool_name="unknown_tool",
                    arguments={},
                    agent_id="claude",
                ),
                decision=Decision(
                    allowed=False,
                    action="deny",
                    reason="No matching rule; default action is 'deny'",
                ),
            ))
            # An allowed event (should NOT appear in fix output)
            await logger.log(AuditEvent(
                tool_call=ToolCall(
                    tool_name="file_read",
                    arguments={"path": "/tmp/ok"},
                    agent_id="claude",
                ),
                decision=Decision(
                    allowed=True,
                    action="allow",
                    policy_name="allow-read",
                ),
            ))
            await logger.flush()
        finally:
            await logger.close()

    asyncio.run(_seed())
    return db_path


class TestFixCommand:
    """Tests for avakill fix."""

    def test_fix_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["fix", "--help"])
        assert result.exit_code == 0
        assert "fix" in result.output.lower()

    def test_fix_last_shows_most_recent_denial(
        self, runner: CliRunner, db_with_denials: Path
    ) -> None:
        result = runner.invoke(cli, ["fix", "--last", "--db", str(db_with_denials)])
        assert result.exit_code == 0
        # Most recent denial is the default-deny for unknown_tool
        assert "unknown_tool" in result.output

    def test_fix_all_shows_all_denials(
        self, runner: CliRunner, db_with_denials: Path
    ) -> None:
        result = runner.invoke(cli, ["fix", "--all", "--db", str(db_with_denials)])
        assert result.exit_code == 0
        assert "file_delete" in result.output
        assert "web_search" in result.output
        assert "unknown_tool" in result.output
        # allowed event should NOT appear
        assert "file_read" not in result.output

    def test_fix_shows_yaml_snippet_for_policy_deny(
        self, runner: CliRunner, db_with_denials: Path
    ) -> None:
        result = runner.invoke(cli, ["fix", "--all", "--db", str(db_with_denials)])
        assert result.exit_code == 0
        # Should contain a YAML snippet for fixing the policy deny
        assert "action: allow" in result.output

    def test_fix_json_output(
        self, runner: CliRunner, db_with_denials: Path
    ) -> None:
        result = runner.invoke(cli, ["fix", "--last", "--json", "--db", str(db_with_denials)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert "hint_type" in data[0]

    def test_fix_no_events(self, runner: CliRunner, tmp_path: Path) -> None:
        empty_db = tmp_path / "empty.db"
        # Create an empty DB
        async def _create():
            logger = SQLiteLogger(str(empty_db))
            try:
                await logger._ensure_db()
            finally:
                await logger.close()
        asyncio.run(_create())

        result = runner.invoke(cli, ["fix", "--db", str(empty_db)])
        assert result.exit_code == 0
        assert "no denied events" in result.output.lower()

    def test_fix_db_not_found(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["fix", "--db", "/nonexistent/path.db"])
        assert result.exit_code != 0

    def test_fix_default_is_last(
        self, runner: CliRunner, db_with_denials: Path
    ) -> None:
        """Running 'avakill fix' with no flags is same as --last."""
        result = runner.invoke(cli, ["fix", "--db", str(db_with_denials)])
        assert result.exit_code == 0
        # Should show exactly 1 denial
        assert "unknown_tool" in result.output
