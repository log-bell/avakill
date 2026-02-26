"""AvaKill dashboard command - Rich terminal dashboard for real-time monitoring."""

from __future__ import annotations

import ast
import asyncio
import importlib
import json
import logging
import subprocess
import sys
import webbrowser
from datetime import datetime, timezone

if sys.platform != "win32":
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


def _git(args: list[str], cwd: Path) -> str:
    """Run a git command and return stripped stdout. Empty string on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def collect_git_state(root: Path) -> dict:
    """Collect current git working tree state."""
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], root)
    head_sha = _git(["rev-parse", "--short", "HEAD"], root)
    head_message = _git(["log", "-1", "--format=%s"], root)

    status_raw = _git(["status", "--porcelain"], root)
    staged: list[str] = []
    modified: list[str] = []
    untracked: list[str] = []
    for line in status_raw.splitlines():
        if len(line) < 4:
            continue
        index_status = line[0]
        worktree_status = line[1]
        filepath = line[3:]
        if index_status == "?":
            untracked.append(filepath)
        elif index_status != " ":
            staged.append(filepath)
        if worktree_status == "M":
            modified.append(filepath)

    dirty = bool(staged or modified or untracked)

    log_raw = _git(["log", "--format=%H|%h|%s|%ar", "-10"], root)
    recent_commits = []
    for line in log_raw.splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4:
            recent_commits.append(
                {
                    "sha": parts[1],
                    "message": parts[2],
                    "age": parts[3],
                }
            )

    stash_raw = _git(["stash", "list", "--format=%gd|%gs"], root)
    stashes = []
    for line in stash_raw.splitlines():
        parts = line.split("|", 1)
        if len(parts) == 2:
            stashes.append({"ref": parts[0], "message": parts[1]})

    return {
        "branch": branch,
        "head_sha": head_sha,
        "head_message": head_message,
        "dirty": dirty,
        "staged": staged,
        "modified": modified,
        "untracked": untracked,
        "recent_commits": recent_commits,
        "stashes": stashes,
    }


def collect_module_graph(package_root: Path) -> dict:
    """Build a module dependency graph from AST imports."""
    nodes: list[dict] = []
    edges: list[dict] = []
    subpackages: set[str] = set()

    module_ids: dict[Path, str] = {}
    for py_file in sorted(package_root.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue
        rel = py_file.relative_to(package_root)
        parts = list(rel.with_suffix("").parts)
        module_id = ".".join(parts)
        module_ids[py_file] = module_id

        if len(parts) > 1:
            subpackages.add(parts[0])

        loc = len(py_file.read_text(errors="replace").splitlines())
        mod_type = parts[0] if len(parts) > 1 else "root"

        nodes.append(
            {
                "id": module_id,
                "path": str(py_file.relative_to(package_root.parent.parent)),
                "loc": loc,
                "type": mod_type,
            }
        )

    known_ids = {n["id"] for n in nodes}

    for py_file, module_id in module_ids.items():
        try:
            source = py_file.read_text(errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                targets = [node.module]

            for target in targets:
                if target.startswith("avakill."):
                    target = target[len("avakill.") :]

                parts = target.split(".")
                for i in range(len(parts), 0, -1):
                    candidate = ".".join(parts[:i])
                    if candidate in known_ids and candidate != module_id:
                        edges.append({"from": module_id, "to": candidate})
                        break

    seen: set[tuple[str, str]] = set()
    unique_edges = []
    for e in edges:
        key = (e["from"], e["to"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(e)

    return {
        "nodes": nodes,
        "edges": unique_edges,
        "subpackages": sorted(subpackages),
    }


def collect_health() -> dict:
    """Return initial (stale) health state for all four checks."""
    stale = {"status": "stale", "last_run": None}
    return {
        "tests": {**stale},
        "lint": {**stale},
        "typecheck": {**stale},
        "go_build": {**stale},
    }


_CHECK_COMMANDS: dict[str, list[str]] = {
    "tests": ["python", "-m", "pytest", "--tb=short", "-q"],
    "lint": ["python", "-m", "ruff", "check", "."],
    "typecheck": ["python", "-m", "mypy", "src/avakill"],
    "go_build": ["go", "build", "./cmd/avakill-shim/..."],
}


def run_health_check(check_name: str, root: Path) -> dict:
    """Run a single health check and return its result."""
    cmd = _CHECK_COMMANDS.get(check_name)
    if not cmd:
        return {"status": "fail", "error": f"Unknown check: {check_name}", "last_run": None}

    try:
        result = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=120)
        now = datetime.now(timezone.utc).isoformat()

        if result.returncode == 0:
            return {
                "status": "pass",
                "output": result.stdout[-500:] if result.stdout else "",
                "last_run": now,
            }
        else:
            error = result.stderr[-500:] if result.stderr else result.stdout[-500:]
            return {
                "status": "fail",
                "error": error,
                "output": result.stdout[-500:] if result.stdout else "",
                "last_run": now,
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "fail",
            "error": f"{check_name} timed out after 120s",
            "last_run": datetime.now(timezone.utc).isoformat(),
        }
    except FileNotFoundError:
        return {
            "status": "fail",
            "error": f"Command not found: {cmd[0]}",
            "last_run": datetime.now(timezone.utc).isoformat(),
        }


def collect_cli_commands() -> dict:
    """Introspect Click command tree and return structured CLI reference."""
    from avakill.cli.main import _COMMAND_GROUPS, _COMMANDS

    def _extract_command(name: str) -> dict | None:
        module_path, attr_name = _COMMANDS[name]
        try:
            mod = importlib.import_module(module_path)
            cmd = getattr(mod, attr_name)
        except Exception:
            return None

        info: dict[str, Any] = {
            "name": name,
            "help": cmd.help or "",
        }

        # Extract parameters (skip the Click context)
        params = []
        for p in cmd.params:
            if isinstance(p, click.Argument):
                params.append(
                    {
                        "name": p.name,
                        "kind": "argument",
                        "required": p.required,
                    }
                )
            elif isinstance(p, click.Option):
                params.append(
                    {
                        "name": p.name,
                        "kind": "option",
                        "flags": list(p.opts),
                        "help": p.help or "",
                        "default": str(p.default) if p.default is not None else None,
                        "is_flag": p.is_flag,
                    }
                )
        info["params"] = params

        # Recurse into subcommands for Groups
        if isinstance(cmd, click.Group):
            subs = []
            for sub_name in cmd.list_commands(click.Context(cmd, info_name=name)):
                sub_cmd = cmd.get_command(click.Context(cmd, info_name=name), sub_name)
                if sub_cmd is None:
                    continue
                sub_info: dict[str, Any] = {
                    "name": sub_name,
                    "help": sub_cmd.help or "",
                }
                sub_params = []
                for p in sub_cmd.params:
                    if isinstance(p, click.Argument):
                        sub_params.append(
                            {
                                "name": p.name,
                                "kind": "argument",
                                "required": p.required,
                            }
                        )
                    elif isinstance(p, click.Option):
                        sub_params.append(
                            {
                                "name": p.name,
                                "kind": "option",
                                "flags": list(p.opts),
                                "help": p.help or "",
                                "default": (str(p.default) if p.default is not None else None),
                                "is_flag": p.is_flag,
                            }
                        )
                sub_info["params"] = sub_params
                subs.append(sub_info)
            info["subcommands"] = subs

        return info

    groups = []
    for group_name, cmd_names in _COMMAND_GROUPS:
        commands = []
        for name in cmd_names:
            if name not in _COMMANDS:
                continue
            cmd_info = _extract_command(name)
            if cmd_info:
                commands.append(cmd_info)
        groups.append({"group": group_name, "commands": commands})

    return {"groups": groups, "total_commands": len(_COMMANDS)}


def build_snapshot(root: Path, health_state: dict | None = None) -> dict:
    """Build a complete dashboard snapshot."""
    name = root.name
    version = "unknown"
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        for line in pyproject.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("version") and "=" in stripped:
                version = stripped.split("=", 1)[1].strip().strip('"')
            elif stripped.startswith("name") and "=" in stripped:
                name = stripped.split("=", 1)[1].strip().strip('"')

    package_root = root / "src" / "avakill"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project": {
            "name": name,
            "version": version,
            "root": str(root),
        },
        "git": collect_git_state(root),
        "modules": collect_module_graph(package_root)
        if package_root.exists()
        else {"nodes": [], "edges": [], "subpackages": []},
        "health": health_state if health_state is not None else collect_health(),
        "cli": collect_cli_commands(),
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


def _make_footer(status_msg: str | None = None) -> Panel:
    """Build the keyboard shortcut footer."""
    keys = Text()
    keys.append("  q ", style="bold white on dark_green")
    keys.append(" quit  ", style="dim")
    keys.append("  r ", style="bold white on dark_green")
    keys.append(" reload policy  ", style="dim")
    keys.append("  c ", style="bold white on dark_green")
    keys.append(" clear  ", style="dim")
    if status_msg:
        keys.append(f"  [{status_msg}]", style="bold yellow")
    return Panel(keys, style="dim", padding=(0, 1))


def _build_layout(
    stats: dict[str, Any],
    events: list[AuditEvent],
    status_msg: str | None = None,
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
    layout["footer"].update(_make_footer(status_msg))
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
        self._cleared = False
        self._status_msg: str | None = None

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

        if self._cleared:
            # After a clear, record what's in the DB so we don't re-show it.
            # Only new events arriving after the clear will appear.
            recent = await logger.query(limit=_MAX_LIVE_EVENTS)
            self._cleared_ids = {e.id for e in recent}
            self._cleared = False
            return

        recent = await logger.query(limit=_MAX_LIVE_EVENTS)
        # Merge DB events with live events, deduplicate by id
        seen_ids = {e.id for e in self._events}
        cleared_ids: set[str] = getattr(self, "_cleared_ids", set())
        for event in recent:
            if event.id not in seen_ids and event.id not in cleared_ids:
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
                        self._cleared = True
                        self._status_msg = "Cleared"

                await self._refresh_data(logger)
                live.update(_build_layout(self._stats, list(self._events), self._status_msg))
                self._status_msg = None
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
        if self._guard is None:
            self._status_msg = "No policy loaded"
            return
        try:
            self._guard.reload_policy()
            self._status_msg = "Policy reloaded"
        except Exception:
            self._status_msg = "Reload failed"
            logging.getLogger(__name__).warning("Manual policy reload failed", exc_info=True)


def _check_deps() -> None:
    """Check that dashboard dependencies are installed."""
    missing = []
    try:
        import aiohttp  # noqa: F401
    except ImportError:
        missing.append("aiohttp")
    try:
        import watchfiles  # noqa: F401
    except ImportError:
        missing.append("watchfiles")
    if missing:
        click.echo(
            f"Missing dependencies: {', '.join(missing)}\n"
            'Install with: pip install "avakill[dashboard]"',
            err=True,
        )
        raise SystemExit(1)


async def _serve(root: Path, port: int, no_open: bool, host: str = "localhost") -> None:
    """Run the dashboard aiohttp server with WebSocket and file watcher."""
    from aiohttp import web
    from watchfiles import awatch

    health_state = collect_health()
    clients: set[web.WebSocketResponse] = set()

    async def broadcast(snapshot: dict) -> None:
        payload = json.dumps(snapshot)
        closed = set()
        for ws in clients:
            try:
                await ws.send_str(payload)
            except (ConnectionResetError, Exception):
                closed.add(ws)
        clients.difference_update(closed)

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        clients.add(ws)

        # Send initial snapshot
        snapshot = build_snapshot(root, health_state)
        await ws.send_str(json.dumps(snapshot))

        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue

                if data.get("action") == "run_check":
                    check_name = data.get("check", "")
                    if check_name in health_state:
                        health_state[check_name] = {
                            "status": "running",
                            "last_run": health_state[check_name].get("last_run"),
                        }
                        await broadcast(build_snapshot(root, health_state))

                        result = await asyncio.to_thread(run_health_check, check_name, root)
                        health_state[check_name] = result
                        await broadcast(build_snapshot(root, health_state))

        clients.discard(ws)
        return ws

    # Resolve the dashboard HTML path
    site_dir = root / "site" / "dashboard"
    index_file = site_dir / "index.html"

    async def index_handler(request: web.Request) -> web.Response:
        if not index_file.exists():
            return web.Response(text="Dashboard HTML not found", status=404)
        return web.FileResponse(index_file)

    app = web.Application()
    app.router.add_get("/", index_handler)
    app.router.add_get("/ws", ws_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    url = f"http://{host}:{port}"
    click.echo("\n  AvaKill Dashboard")
    click.echo(f"  {url}")
    if host == "0.0.0.0":
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()
        click.echo(f"  Network: http://{local_ip}:{port}")
    click.echo(f"  Watching: {root}")
    click.echo("  Press Ctrl+C to stop\n")

    if not no_open:
        webbrowser.open(url)

    # File watcher loop
    watch_extensions = {".py", ".go", ".yaml", ".yml", ".toml", ".md"}
    ignore_dirs = {
        "__pycache__",
        ".git",
        "node_modules",
        ".venv",
        "build",
        "dist",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }

    try:
        async for changes in awatch(root, debounce=300, step=100):
            relevant = False
            for _change_type, path_str in changes:
                p = Path(path_str)
                if any(part in ignore_dirs for part in p.parts):
                    continue
                if p.suffix in watch_extensions:
                    relevant = True
                    break

            if relevant:
                snapshot = build_snapshot(root, health_state)
                await broadcast(snapshot)
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()


@click.command("dashboard")
@click.option("--port", default=7700, show_default=True, help="HTTP port for dashboard.")
@click.option(
    "--host",
    default="localhost",
    show_default=True,
    help="Bind address (use 0.0.0.0 for network access).",
)
@click.option("--no-open", is_flag=True, help="Don't auto-open browser.")
@click.option("--root", default=".", help="Project root directory.")
def dashboard(port: int, host: str, no_open: bool, root: str) -> None:
    """Start the real-time codebase visualization dashboard."""
    _check_deps()
    root_path = Path(root).resolve()
    if not (root_path / ".git").exists():
        click.echo("Warning: not a git repository", err=True)
    try:
        asyncio.run(_serve(root_path, port, no_open, host))
    except KeyboardInterrupt:
        click.echo("\nDashboard stopped.")
