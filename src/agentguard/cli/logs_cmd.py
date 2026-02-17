"""AgentGuard logs command - query and display audit logs."""

from __future__ import annotations

import asyncio
import contextlib
import json as json_mod
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from agentguard.core.models import AuditEvent
from agentguard.logging.sqlite_logger import SQLiteLogger

_ACTION_STYLE: dict[str, tuple[str, str]] = {
    "allow": ("green", "ALLOW"),
    "deny": ("red", "DENY"),
    "require_approval": ("yellow", "PEND"),
}


def _parse_since(since: str) -> datetime:
    """Parse a --since value into a UTC datetime.

    Accepts relative durations like '1h', '30m', '7d' or ISO timestamps.
    """
    since = since.strip()
    now = datetime.now(timezone.utc)

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if since[-1] in multipliers and since[:-1].isdigit():
        seconds = int(since[:-1]) * multipliers[since[-1]]
        return now - timedelta(seconds=seconds)

    return datetime.fromisoformat(since)


def _event_to_dict(event: AuditEvent) -> dict[str, Any]:
    """Convert an AuditEvent to a JSON-serialisable dict."""
    return {
        "id": event.id,
        "timestamp": event.tool_call.timestamp.isoformat(),
        "tool": event.tool_call.tool_name,
        "arguments": event.tool_call.arguments,
        "action": event.decision.action,
        "allowed": event.decision.allowed,
        "policy": event.decision.policy_name,
        "reason": event.decision.reason,
        "agent_id": event.tool_call.agent_id,
        "session_id": event.tool_call.session_id,
        "latency_ms": event.decision.latency_ms,
    }


def _build_filters(
    tool: str | None,
    denied_only: bool,
    agent: str | None,
    session: str | None,
    since: str | None,
) -> dict[str, Any] | None:
    """Build a filter dict for SQLiteLogger.query()."""
    filters: dict[str, Any] = {}
    if tool:
        filters["tool_name"] = tool
    if denied_only:
        filters["decision_allowed"] = False
    if agent:
        filters["agent_id"] = agent
    if session:
        filters["session_id"] = session
    if since:
        filters["time_after"] = _parse_since(since)
    return filters or None


def _render_table(events: list[AuditEvent], console: Console) -> None:
    """Render events as a Rich table."""
    table = Table(title="AgentGuard Audit Log", expand=True, show_lines=False)
    table.add_column("Time", style="dim", width=20, no_wrap=True)
    table.add_column("Tool", style="cyan", min_width=14)
    table.add_column("Action", width=8, no_wrap=True)
    table.add_column("Policy", style="dim", min_width=12)
    table.add_column("Agent", style="dim", max_width=16)
    table.add_column("Reason", style="dim", max_width=40)

    for event in events:
        ts = event.tool_call.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        tool = event.tool_call.tool_name
        action = event.decision.action
        style, label = _ACTION_STYLE.get(action, ("white", action.upper()))
        action_text = Text(label, style=style)
        policy = event.decision.policy_name or ""
        agent_id = event.tool_call.agent_id or ""
        reason = event.decision.reason or ""
        if len(reason) > 40:
            reason = reason[:37] + "..."

        table.add_row(ts, tool, action_text, policy, agent_id, reason)

    console.print(table)
    console.print(f"[dim]{len(events)} event(s) shown[/dim]")


def _render_json(events: list[AuditEvent]) -> None:
    """Render events as JSON to stdout."""
    records = [_event_to_dict(e) for e in events]
    sys.stdout.write(json_mod.dumps(records, indent=2) + "\n")


async def _query_events(
    db: str,
    filters: dict[str, Any] | None,
    limit: int,
) -> list[AuditEvent]:
    """Open the database and query events."""
    logger = SQLiteLogger(db)
    try:
        return await logger.query(filters=filters, limit=limit)
    finally:
        await logger.close()


async def _tail_events(
    db: str,
    filters: dict[str, Any] | None,
    fmt: str,
) -> None:
    """Follow events in real-time, similar to tail -f."""
    console = Console()
    logger = SQLiteLogger(db)

    try:
        await logger._ensure_db()

        # Get the most recent event id to start from
        recent = await logger.query(filters=filters, limit=1)
        last_seen: set[str] = set()
        if recent:
            last_seen.add(recent[0].id)
            if fmt == "table":
                _render_table(recent, console)
            else:
                _render_json(recent)

        console.print("[dim]Following new events... (Ctrl+C to stop)[/dim]")

        while True:
            await asyncio.sleep(0.5)
            events = await logger.query(filters=filters, limit=20)
            new_events = [e for e in events if e.id not in last_seen]
            if new_events:
                # Show in chronological order
                new_events.reverse()
                for event in new_events:
                    last_seen.add(event.id)
                if fmt == "table":
                    _render_table(new_events, console)
                else:
                    _render_json(new_events)
    finally:
        await logger.close()


@click.group(invoke_without_command=True)
@click.option("--db", default="agentguard_audit.db", help="Path to the audit database.")
@click.option("--tool", default=None, help="Filter by tool name (supports globs).")
@click.option("--limit", default=50, help="Maximum number of log entries to display.")
@click.option("--denied-only", is_flag=True, help="Show only denied events.")
@click.option("--agent", default=None, help="Filter by agent ID.")
@click.option("--session", default=None, help="Filter by session ID.")
@click.option("--since", default=None, help="Show events after this time (e.g. '1h', '30m', '7d').")
@click.option("--json", "fmt", flag_value="json", default=False, help="Output as JSON.")
@click.pass_context
def logs(
    ctx: click.Context,
    db: str,
    tool: str | None,
    limit: int,
    denied_only: bool,
    agent: str | None,
    session: str | None,
    since: str | None,
    fmt: str | bool,
) -> None:
    """Query and display audit logs."""
    # Store params for subcommands
    ctx.ensure_object(dict)
    ctx.obj["db"] = db
    ctx.obj["tool"] = tool
    ctx.obj["denied_only"] = denied_only
    ctx.obj["agent"] = agent
    ctx.obj["session"] = session
    ctx.obj["since"] = since
    ctx.obj["fmt"] = "json" if fmt else "table"

    if ctx.invoked_subcommand is not None:
        return

    # Default: show recent logs
    output_format = "json" if fmt else "table"
    db_path = Path(db).expanduser()
    if not db_path.exists():
        console = Console()
        console.print(f"[yellow]Database not found:[/yellow] {db_path}")
        raise SystemExit(1)

    filters = _build_filters(tool, denied_only, agent, session, since)
    events = asyncio.run(_query_events(str(db_path), filters, limit))

    if not events:
        console = Console()
        console.print("[dim]No events found.[/dim]")
        return

    if output_format == "json":
        _render_json(events)
    else:
        _render_table(events, Console())


@logs.command()
@click.pass_context
def tail(ctx: click.Context) -> None:
    """Follow new audit events in real-time (like tail -f)."""
    params = ctx.obj
    db_path = Path(params["db"]).expanduser()
    filters = _build_filters(
        params["tool"],
        params["denied_only"],
        params["agent"],
        params["session"],
        params["since"],
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_tail_events(str(db_path), filters, params["fmt"]))
