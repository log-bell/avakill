"""Tests for the approval request store."""

from __future__ import annotations

from pathlib import Path

import pytest

from avakill.core.approval import ApprovalStore
from avakill.core.models import Decision, ToolCall


def _make_tool_call(tool: str = "file_write") -> ToolCall:
    return ToolCall(tool_name=tool, arguments={"path": "/etc/passwd"})


def _make_decision() -> Decision:
    return Decision(
        allowed=False,
        action="require_approval",
        policy_name="approve-writes",
        reason="Write requires human approval",
    )


class TestApprovalStore:
    """Tests for ApprovalStore."""

    async def test_create_request(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            req = await store.create(_make_tool_call(), _make_decision(), agent="claude-code")
            assert req.id is not None
            assert req.status == "pending"
            assert req.agent == "claude-code"
            assert req.tool_call.tool_name == "file_write"
            assert req.expires_at is not None

    async def test_approve_request(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            req = await store.create(_make_tool_call(), _make_decision(), agent="claude-code")
            updated = await store.approve(req.id, approver="admin")
            assert updated.status == "approved"
            assert updated.approved_by == "admin"

    async def test_deny_request(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            req = await store.create(_make_tool_call(), _make_decision(), agent="gemini-cli")
            updated = await store.deny(req.id, approver="security-team")
            assert updated.status == "denied"
            assert updated.approved_by == "security-team"

    async def test_get_pending_excludes_resolved(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            req1 = await store.create(_make_tool_call("file_write"), _make_decision(), agent="a")
            await store.create(_make_tool_call("file_delete"), _make_decision(), agent="b")
            await store.approve(req1.id, approver="admin")

            pending = await store.get_pending()
            assert len(pending) == 1
            assert pending[0].tool_call.tool_name == "file_delete"

    async def test_cleanup_expired(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            # Create a request with 0 TTL (already expired)
            req = await store.create(_make_tool_call(), _make_decision(), agent="a", ttl_seconds=0)
            cleaned = await store.cleanup_expired()
            assert cleaned == 1

            fetched = await store.get(req.id)
            assert fetched is not None
            assert fetched.status == "expired"

    async def test_approve_nonexistent_raises(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            with pytest.raises(KeyError, match="not found"):
                await store.approve("nonexistent-id", approver="admin")

    async def test_get_returns_none_for_unknown_id(self, tmp_path: Path) -> None:
        db = tmp_path / "approvals.db"
        async with ApprovalStore(db) as store:
            result = await store.get("unknown-id")
            assert result is None
