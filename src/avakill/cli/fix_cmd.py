"""AvaKill fix command -- show recovery steps for recent denials."""

from __future__ import annotations

import asyncio
import json as json_mod
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from avakill.core.models import AuditEvent
from avakill.core.recovery import RecoveryHint, recovery_hint_for
from avakill.logging.sqlite_logger import SQLiteLogger

_DEFAULT_DB = "avakill_audit.db"


def _hint_to_dict(event: AuditEvent, hint: RecoveryHint | None) -> dict[str, Any]:
    """Serialize an event + hint for JSON output."""
    base: dict[str, Any] = {
        "event_id": event.id,
        "tool": event.tool_call.tool_name,
        "arguments": event.tool_call.arguments,
        "reason": event.decision.reason,
        "policy": event.decision.policy_name,
        "timestamp": event.tool_call.timestamp.isoformat(),
    }
    if hint:
        base["hint_type"] = hint.hint_type
        base["summary"] = hint.summary
        base["commands"] = list(hint.commands)
        base["yaml_snippet"] = hint.yaml_snippet
        base["wait_seconds"] = hint.wait_seconds
        base["steps"] = list(hint.steps)
    else:
        base["hint_type"] = None
        base["summary"] = None
        base["commands"] = []
        base["yaml_snippet"] = None
        base["wait_seconds"] = None
        base["steps"] = []
    return base


def _render_fix_card(event: AuditEvent, hint: RecoveryHint | None, console: Console) -> None:
    """Render a single Rich fix card for a denied event."""
    body = Text()

    # Header info
    body.append("Tool: ", style="bold")
    body.append(f"{event.tool_call.tool_name}\n")
    body.append("Time: ", style="bold")
    body.append(f"{event.tool_call.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
    if event.decision.policy_name:
        body.append("Rule: ", style="bold")
        body.append(f"{event.decision.policy_name}\n")
    body.append("Reason: ", style="bold")
    body.append(f"{event.decision.reason or 'Unknown'}\n")

    if hint is None:
        body.append("\nNo recovery suggestion available.\n", style="dim")
        console.print(Panel(body, title="Denied", border_style="red", padding=(1, 2)))
        return

    body.append("\n")
    body.append(hint.summary + "\n", style="bold yellow")

    # Commands
    if hint.commands:
        body.append("\nRun:\n", style="bold green")
        for cmd in hint.commands:
            body.append(f"  $ {cmd}\n", style="green")

    # Wait info
    if hint.wait_seconds is not None:
        body.append(f"\nRate limit resets in ~{hint.wait_seconds}s.\n", style="yellow")

    console.print(Panel(body, title="Fix", border_style="red", padding=(1, 2)))

    # YAML snippet printed outside the panel for easy copy-paste
    if hint.yaml_snippet:
        console.print(Text("Add to your avakill.yaml:", style="bold"))
        console.print(Syntax(hint.yaml_snippet, "yaml", theme="monokai", padding=1))
        console.print()


async def _query_denied(db: str, limit: int) -> list[AuditEvent]:
    """Query denied events from the audit DB."""
    logger = SQLiteLogger(db)
    try:
        return await logger.query(filters={"decision_allowed": False}, limit=limit)
    finally:
        await logger.close()


@click.command()
@click.option("--last", "show_last", is_flag=True, default=False, help="Show only the most recent denial (default behavior).")
@click.option("--all", "show_all", is_flag=True, default=False, help="Show all recent denials (up to 20).")
@click.option("--db", default=_DEFAULT_DB, help="Path to the audit database.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output as JSON.")
def fix(show_last: bool, show_all: bool, db: str, output_json: bool) -> None:
    """Show recovery steps for recent policy denials.

    By default, shows the most recent denied event with actionable
    fix suggestions including copy-pasteable commands and YAML snippets.

    \b
    Examples:
      avakill fix              # most recent denial
      avakill fix --all        # all recent denials
      avakill fix --json       # machine-readable output
    """
    db_path = Path(db).expanduser()
    if not db_path.exists():
        console = Console(stderr=True)
        console.print(f"[red]Database not found:[/red] {db_path}")
        raise SystemExit(1)

    limit = 20 if show_all else 1
    events = asyncio.run(_query_denied(str(db_path), limit))

    if not events:
        console = Console()
        console.print("[dim]No denied events found.[/dim]")
        return

    hints = [(e, recovery_hint_for(e.decision, tool_name=e.tool_call.tool_name)) for e in events]

    if output_json:
        records = [_hint_to_dict(e, h) for e, h in hints]
        sys.stdout.write(json_mod.dumps(records, indent=2) + "\n")
        return

    console = Console()
    for event, hint in hints:
        _render_fix_card(event, hint, console)
