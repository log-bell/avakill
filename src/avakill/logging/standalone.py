"""Shared fire-and-forget audit logging for standalone (non-daemon) evaluation.

Used by both hook adapters and the MCP proxy when evaluating in-process
via Guard or a policy file.  Uses synchronous stdlib sqlite3 — never
aiosqlite — because callers are short-lived or latency-insensitive.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from avakill.core.models import Decision


def try_log_to_audit_db(
    tool: str,
    args: dict | None,
    decision: Decision,
    agent_id: str | None = None,
    latency_ms: float = 0.0,
) -> None:
    """Best-effort log an audit event directly to the SQLite audit DB.

    Uses synchronous stdlib ``sqlite3`` (not aiosqlite) since hooks and
    MCP proxy evaluations are short-lived.  Never raises — silently drops
    on any error so callers are never affected.
    """
    with contextlib.suppress(Exception):
        from avakill.cli.config import get_audit_db_path, is_tracking_enabled

        if not is_tracking_enabled():
            return

        db_path = Path(get_audit_db_path()).expanduser()
        if not db_path.exists():
            return

        now = datetime.now(timezone.utc).isoformat()
        row = (
            str(uuid4()),
            now,
            None,  # session_id
            agent_id,
            tool,
            json.dumps(args) if args else "{}",
            int(decision.allowed),
            decision.action,
            decision.policy_name,
            decision.reason,
            latency_ms,
            None,  # execution_result
            None,  # error
            None,  # metadata
        )

        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )
            conn.commit()
        finally:
            conn.close()
