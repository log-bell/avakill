"""SQLite-backed approval request store for human-in-the-loop workflows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import aiosqlite
from pydantic import BaseModel, Field

from avakill.core.models import Decision, ToolCall

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    tool_args TEXT NOT NULL,
    agent TEXT NOT NULL,
    decision_action TEXT NOT NULL,
    decision_policy TEXT,
    decision_reason TEXT,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TEXT,
    approved_by TEXT
)"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)",
    "CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approvals(agent)",
    "CREATE INDEX IF NOT EXISTS idx_approvals_timestamp ON approvals(timestamp DESC)",
]


class ApprovalRequest(BaseModel):
    """A pending approval request for a tool call that requires human review."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    tool_call: ToolCall
    decision: Decision
    agent: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: Literal["pending", "approved", "denied", "expired"] = "pending"
    expires_at: datetime | None = None
    approved_by: str | None = None


class ApprovalStore:
    """SQLite-backed store for approval requests.

    Follows the same async SQLite pattern as
    :class:`avakill.logging.sqlite_logger.SQLiteLogger`.

    Usage::

        async with ApprovalStore("/tmp/approvals.db") as store:
            req = await store.create(tool_call, decision, agent="claude-code")
            await store.approve(req.id, approver="admin")
    """

    def __init__(self, db_path: str | Path = "~/.avakill/approvals.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db: aiosqlite.Connection | None = None
        self._initialised = False

    async def _ensure_db(self) -> aiosqlite.Connection:
        """Open the connection and create schema if needed."""
        if self._db is not None and self._initialised:
            return self._db

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute(_CREATE_TABLE)
        for idx_sql in _CREATE_INDEXES:
            await self._db.execute(idx_sql)
        await self._db.commit()
        self._initialised = True
        return self._db

    async def create(
        self,
        tool_call: ToolCall,
        decision: Decision,
        agent: str,
        ttl_seconds: int = 3600,
    ) -> ApprovalRequest:
        """Create a new pending approval request.

        Args:
            tool_call: The tool call awaiting approval.
            decision: The policy decision that triggered the approval request.
            agent: The agent that made the tool call.
            ttl_seconds: Time-to-live in seconds before the request expires.

        Returns:
            The created ApprovalRequest.
        """
        import json

        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        req = ApprovalRequest(
            tool_call=tool_call,
            decision=decision,
            agent=agent,
            timestamp=now,
            expires_at=expires,
        )
        db = await self._ensure_db()
        await db.execute(
            "INSERT INTO approvals "
            "(id, tool_name, tool_args, agent, decision_action, decision_policy, "
            "decision_reason, timestamp, status, expires_at, approved_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                req.id,
                tool_call.tool_name,
                json.dumps(tool_call.arguments),
                agent,
                decision.action,
                decision.policy_name,
                decision.reason,
                req.timestamp.isoformat(),
                req.status,
                req.expires_at.isoformat() if req.expires_at else None,
                req.approved_by,
            ),
        )
        await db.commit()
        return req

    async def approve(self, request_id: str, approver: str) -> ApprovalRequest:
        """Approve a pending request.

        Args:
            request_id: The ID of the approval request.
            approver: Who approved it.

        Returns:
            The updated ApprovalRequest.

        Raises:
            KeyError: If the request is not found.
        """
        req = await self.get(request_id)
        if req is None:
            raise KeyError(f"Approval request '{request_id}' not found")
        db = await self._ensure_db()
        await db.execute(
            "UPDATE approvals SET status = 'approved', approved_by = ? WHERE id = ?",
            (approver, request_id),
        )
        await db.commit()
        return ApprovalRequest(
            id=req.id,
            tool_call=req.tool_call,
            decision=req.decision,
            agent=req.agent,
            timestamp=req.timestamp,
            status="approved",
            expires_at=req.expires_at,
            approved_by=approver,
        )

    async def deny(self, request_id: str, approver: str) -> ApprovalRequest:
        """Deny a pending request.

        Args:
            request_id: The ID of the approval request.
            approver: Who denied it.

        Returns:
            The updated ApprovalRequest.

        Raises:
            KeyError: If the request is not found.
        """
        req = await self.get(request_id)
        if req is None:
            raise KeyError(f"Approval request '{request_id}' not found")
        db = await self._ensure_db()
        await db.execute(
            "UPDATE approvals SET status = 'denied', approved_by = ? WHERE id = ?",
            (approver, request_id),
        )
        await db.commit()
        return ApprovalRequest(
            id=req.id,
            tool_call=req.tool_call,
            decision=req.decision,
            agent=req.agent,
            timestamp=req.timestamp,
            status="denied",
            expires_at=req.expires_at,
            approved_by=approver,
        )

    async def get_approved_for_tool(self, tool_name: str, agent: str) -> ApprovalRequest | None:
        """Return the most recent approved request for a given tool and agent.

        Args:
            tool_name: The canonical tool name.
            agent: The agent identifier.

        Returns:
            The matching :class:`ApprovalRequest`, or ``None``.
        """
        db = await self._ensure_db()
        now = datetime.now(timezone.utc).isoformat()
        cursor = await db.execute(
            "SELECT * FROM approvals "
            "WHERE status = 'approved' AND tool_name = ? AND agent = ? "
            "AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY timestamp DESC LIMIT 1",
            (tool_name, agent, now),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_request(row)

    async def resolve_id(self, request_id: str) -> str | None:
        """Resolve a possibly-abbreviated request ID to its full UUID.

        Args:
            request_id: Full or prefix of a request UUID.

        Returns:
            The full UUID string, or ``None`` if no match is found.

        Raises:
            KeyError: If the prefix matches more than one request.
        """
        if len(request_id) >= 32:
            # Looks like a full UUID — check existence directly
            req = await self.get(request_id)
            return req.id if req is not None else None

        db = await self._ensure_db()
        cursor = await db.execute(
            "SELECT id FROM approvals WHERE id LIKE ?",
            (request_id + "%",),
        )
        rows: list[Any] = list(await cursor.fetchall())
        if len(rows) == 0:
            return None
        if len(rows) > 1:
            raise KeyError(f"Ambiguous ID prefix '{request_id}' matches {len(rows)} requests")
        return str(rows[0][0])

    async def get_pending(self) -> list[ApprovalRequest]:
        """Return all pending (non-expired) approval requests."""
        db = await self._ensure_db()
        now = datetime.now(timezone.utc).isoformat()
        cursor = await db.execute(
            "SELECT * FROM approvals WHERE status = 'pending' "
            "AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY timestamp DESC",
            (now,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_request(row) for row in rows]

    async def get(self, request_id: str) -> ApprovalRequest | None:
        """Get a specific approval request by ID."""
        db = await self._ensure_db()
        cursor = await db.execute("SELECT * FROM approvals WHERE id = ?", (request_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_request(row)

    async def cleanup_expired(self) -> int:
        """Mark expired pending requests as 'expired'.

        Returns:
            The number of requests marked as expired.
        """
        db = await self._ensure_db()
        now = datetime.now(timezone.utc).isoformat()
        cursor = await db.execute(
            "UPDATE approvals SET status = 'expired' "
            "WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )
        await db.commit()
        return cursor.rowcount

    async def close(self) -> None:
        """Close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None
            self._initialised = False

    async def __aenter__(self) -> ApprovalStore:
        await self._ensure_db()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    @staticmethod
    def _row_to_request(row: Any) -> ApprovalRequest:
        """Reconstruct an ApprovalRequest from a database row."""
        import json

        (
            id_,
            tool_name,
            tool_args,
            agent,
            decision_action,
            decision_policy,
            decision_reason,
            timestamp,
            status,
            expires_at,
            approved_by,
        ) = tuple(row)

        tool_call = ToolCall(
            tool_name=tool_name,
            arguments=json.loads(tool_args) if tool_args else {},
        )
        decision = Decision(
            allowed=decision_action == "allow",
            action=decision_action,
            policy_name=decision_policy,
            reason=decision_reason,
        )
        return ApprovalRequest(
            id=id_,
            tool_call=tool_call,
            decision=decision,
            agent=agent,
            timestamp=datetime.fromisoformat(timestamp),
            status=status,
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
            approved_by=approved_by,
        )
