"""AvaKill dashboard command - Rich terminal dashboard for real-time monitoring."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
import termios
import tty
from collections import deque
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from avakill.core.engine import Guard
from avakill.core.models import AuditEvent
from avakill.logging.event_bus import EventBus
from avakill.logging.sqlite_logger import SQLiteLogger

_MAX_LIVE_EVENTS = 20
_BAR_WIDTH = 20

_ACTION_STYLE: dict[str, tuple[str, str]] = {
    "allow": ("bold green", "ALLOW"),
    "deny": ("bold red", "DENY"),
    "require_approval": ("bold yellow", "PEND"),
}


def _make_header(stats: dict[str, Any]) -> Panel:
    """Build the safety overview stats panel."""
    total = stats.get("total_events", 0)
    allowed = stats.get("allowed", 0)
    denied = stats.get("denied", 0)
    pending = total - allowed - denied if total > allowed + denied else 0

    def _pct(n: int) -> str:
        return f"({n / total * 100:.1f}%)" if total else ""

    table = Table(show_header=False, show_edge=False, pad_edge=False, expand=True)
    table.add_column(justify="center", ratio=1)
    table.add_column(justify="center", ratio=1)
    table.add_column(justify="center", ratio=1)
    table.add_column(justify="center", ratio=1)

    table.add_row(
        Text("Total", style="dim"),
        Text("Allowed", style="dim"),
        Text("Denied", style="dim"),
        Text("Pending", style="dim"),
    )
    table.add_row(
        Text(f"{total:,}", style="bold white"),
        Text(f"{allowed:,}", style="bold green"),
        Text(f"{denied:,}", style="bold red"),
        Text(f"{pending:,}", style="bold yellow"),
    )
    table.add_row(
        Text(""),
        Text(_pct(allowed), style="dim green"),
        Text(_pct(denied), style="dim red"),
        Text(_pct(pending), style="dim yellow"),
    )

    return Panel(table, title="Safety Overview", border_style="bright_blue", padding=(1, 2))


def _make_event_table(events: list[AuditEvent]) -> Panel:
    """Build the live tool calls table."""
    table = Table(expand=True, show_lines=False, pad_edge=False)
    table.add_column("Time", style="dim", width=10, no_wrap=True)
    table.add_column("Tool", style="cyan", min_width=16)
    table.add_column("Action", width=10, no_wrap=True)
    table.add_column("Policy", style="dim", min_width=14)

    for event in events:
        ts = event.tool_call.timestamp.strftime("%H:%M:%S")
        tool = event.tool_call.tool_name
        action = event.decision.action
        style, label = _ACTION_STYLE.get(action, ("white", action.upper()))
        action_text = Text(f" {label} ", style=style)
        policy = event.decision.policy_name or ""

        table.add_row(ts, tool, action_text, policy)

        # Show argument preview for denied calls
        if action == "deny" and event.tool_call.arguments:
            args_preview = _format_args_preview(event.tool_call.arguments)
            if args_preview:
                table.add_row("", Text(f"  {args_preview}", style="dim red"), "", "")

    if not events:
        table.add_row("", Text("Waiting for events...", style="dim italic"), "", "")

    return Panel(table, title="Live Tool Calls", border_style="bright_blue", padding=(0, 1))


def _format_args_preview(args: dict[str, Any], max_len: int = 60) -> str:
    """Format arguments as a short preview string."""
    parts: list[str] = []
    for v in args.values():
        s = str(v)
        if len(s) > 40:
            s = s[:37] + "..."
        parts.append(s)
    preview = " | ".join(parts)
    if len(preview) > max_len:
        preview = preview[: max_len - 3] + "..."
    return preview


def _make_denied_bar(stats: dict[str, Any]) -> Panel:
    """Build the top denied tools bar chart."""
    top_denied: list[tuple[str, int]] = stats.get("top_denied_tools", [])
    lines: list[Text] = []

    if top_denied:
        max_count = max(c for _, c in top_denied)
        for tool_name, count in top_denied[:5]:
            filled = int(count / max_count * _BAR_WIDTH) if max_count else 0
            empty = _BAR_WIDTH - filled
            bar = Text()
            bar.append(f"{tool_name:<20s} ", style="cyan")
            bar.append("\u2588" * filled, style="red")
            bar.append("\u2591" * empty, style="dim")
            bar.append(f" {count}", style="bold")
            lines.append(bar)
    else:
        lines.append(Text("No denied calls yet", style="dim italic"))

    body = Text("\n").join(lines)
    return Panel(
        body, title="Top Denied Tools (last hour)", border_style="bright_blue", padding=(1, 2)
    )


def _make_footer() -> Panel:
    """Build the keyboard shortcut footer."""
    keys = Text()
    keys.append("  q ", style="bold white on dark_green")
    keys.append(" quit  ", style="dim")
    keys.append("  r ", style="bold white on dark_green")
    keys.append(" reload policy  ", style="dim")
    keys.append("  c ", style="bold white on dark_green")
    keys.append(" clear  ", style="dim")
    return Panel(keys, style="dim", padding=(0, 1))


def _build_layout(
    stats: dict[str, Any],
    events: list[AuditEvent],
) -> Layout:
    """Assemble the full dashboard layout."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=8),
        Layout(name="body"),
        Layout(name="denied", size=10),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_make_header(stats))
    layout["body"].update(_make_event_table(events))
    layout["denied"].update(_make_denied_bar(stats))
    layout["footer"].update(_make_footer())
    return layout


class _Dashboard:
    """Async dashboard controller."""

    def __init__(
        self,
        db_path: str,
        refresh: float,
        policy: str | None,
        *,
        watch: bool = False,
    ) -> None:
        self._db_path = db_path
        self._refresh = refresh
        self._policy_path = policy
        self._watch = watch
        self._events: deque[AuditEvent] = deque(maxlen=_MAX_LIVE_EVENTS)
        self._stats: dict[str, Any] = {}
        self._running = True
        self._should_clear = False

        # Create a Guard if a policy path was given
        self._guard: Guard | None = None
        if policy:
            self._guard = Guard(policy=policy, self_protection=False)

    async def run(self) -> None:
        console = Console()
        logger = SQLiteLogger(self._db_path)
        _log = logging.getLogger(__name__)

        watcher = None
        try:
            await logger._ensure_db()

            # Start file watcher if requested and a guard is available
            if self._watch and self._guard is not None:
                try:
                    watcher = self._guard.watch()
                    await watcher.start()
                    _log.info("Policy file watcher started")
                except Exception:
                    _log.warning("Could not start policy watcher", exc_info=True)

            # Load initial data
            await self._refresh_data(logger)

            # Subscribe to live events from in-process Guard instances
            bus = EventBus.get()
            unsub = bus.subscribe(self._on_event)

            try:
                with Live(
                    _build_layout(self._stats, list(self._events)),
                    console=console,
                    screen=True,
                    refresh_per_second=4,
                ) as live:
                    await self._loop(live, logger)
            finally:
                unsub()
        finally:
            if watcher is not None:
                await watcher.stop()
            await logger.close()

    def _on_event(self, event: AuditEvent) -> None:
        """EventBus callback for real-time events."""
        self._events.appendleft(event)

    async def _refresh_data(self, logger: SQLiteLogger) -> None:
        """Poll the database for latest stats and events."""
        self._stats = await logger.stats()

        recent = await logger.query(limit=_MAX_LIVE_EVENTS)
        # Merge DB events with live events, deduplicate by id
        seen_ids = {e.id for e in self._events}
        for event in recent:
            if event.id not in seen_ids:
                self._events.append(event)
                seen_ids.add(event.id)

        # Sort newest first, trim to max
        sorted_events = sorted(self._events, key=lambda e: e.tool_call.timestamp, reverse=True)
        self._events = deque(sorted_events[:_MAX_LIVE_EVENTS], maxlen=_MAX_LIVE_EVENTS)

    async def _loop(self, live: Live, logger: SQLiteLogger) -> None:
        """Main refresh loop with keyboard handling."""
        # Set terminal to raw mode for single-char reads
        stdin_fd = sys.stdin.fileno()
        try:
            old_settings = termios.tcgetattr(stdin_fd)
        except termios.error:
            old_settings = None

        if old_settings is not None:
            tty.setcbreak(stdin_fd)

        try:
            while self._running:
                # Check for keyboard input (non-blocking)
                if old_settings is not None:
                    key = await self._read_key(stdin_fd)
                    if key == "q":
                        break
                    elif key == "r":
                        self._reload_policy()
                    elif key == "c":
                        self._events.clear()

                await self._refresh_data(logger)
                live.update(_build_layout(self._stats, list(self._events)))
                await asyncio.sleep(self._refresh)
        finally:
            if old_settings is not None:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)

    async def _read_key(self, fd: int) -> str | None:
        """Non-blocking single-character read from stdin."""
        import select

        loop = asyncio.get_running_loop()
        ready = await loop.run_in_executor(None, lambda: select.select([fd], [], [], 0.05))
        if ready[0]:
            try:
                return sys.stdin.read(1)
            except (OSError, ValueError):
                return None
        return None

    def _reload_policy(self) -> None:
        """Reload policy via the Guard instance."""
        if self._guard is not None:
            try:
                self._guard.reload_policy()
            except Exception:
                logging.getLogger(__name__).warning(
                    "Manual policy reload failed", exc_info=True
                )


@click.command()
@click.option(
    "--db",
    default="avakill_audit.db",
    help="Path to the audit database.",
)
@click.option(
    "--refresh",
    default=0.5,
    type=float,
    help="Refresh interval in seconds.",
)
@click.option(
    "--policy",
    default=None,
    help="Path to the policy file to monitor.",
)
@click.option(
    "--watch/--no-watch",
    default=False,
    help="Automatically reload policy when the file changes on disk.",
)
def dashboard(db: str, refresh: float, policy: str | None, watch: bool) -> None:
    """Launch the real-time terminal dashboard."""
    db_path = Path(db).expanduser()
    if not db_path.exists():
        console = Console()
        console.print(
            f"[yellow]Database not found:[/yellow] {db_path}\n"
            "[dim]The dashboard will create it and wait for events.[/dim]"
        )

    dash = _Dashboard(str(db_path), refresh, policy, watch=watch)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(dash.run())
