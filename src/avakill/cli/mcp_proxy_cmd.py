"""AvaKill mcp-proxy command - start the MCP transparent proxy."""

from __future__ import annotations

import asyncio
import contextlib
import shlex
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from avakill.core.engine import Guard
from avakill.logging.sqlite_logger import SQLiteLogger
from avakill.mcp.proxy import MCPProxyServer


@click.command("mcp-proxy")
@click.option(
    "--upstream-cmd",
    required=True,
    help="Command to run the upstream MCP server.",
)
@click.option(
    "--upstream-args",
    default="",
    help="Arguments for the upstream command (space-separated).",
)
@click.option(
    "--policy",
    default="avakill.yaml",
    help="Path to the policy file.",
)
@click.option(
    "--daemon",
    "daemon_socket",
    default=None,
    help="Evaluate via daemon socket instead of embedded Guard.",
)
@click.option(
    "--agent",
    default="mcp",
    help="Agent name for tool normalization.",
)
@click.option(
    "--log-db",
    default=None,
    help="Path to the audit database (default: no logging).",
)
def mcp_proxy(
    upstream_cmd: str,
    upstream_args: str,
    policy: str,
    daemon_socket: str | None,
    agent: str,
    log_db: str | None,
) -> None:
    """Start the MCP transparent proxy.

    Sits between an MCP client and an upstream MCP server, intercepting
    tools/call requests and evaluating them against the policy.

    \b
    Stdio mode (default):
        avakill mcp-proxy --upstream-cmd npx --upstream-args "-y @anthropic/mcp-fs /path"

    \b
    Daemon mode:
        avakill mcp-proxy --upstream-cmd npx --upstream-args "..." --daemon ~/.avakill/avakill.sock
    """
    console = Console(stderr=True)

    # Parse upstream args
    args_list = shlex.split(upstream_args) if upstream_args else []

    # Determine evaluation mode
    if daemon_socket:
        # Daemon mode — delegate evaluation to the running daemon
        proxy = MCPProxyServer(
            upstream_cmd=upstream_cmd,
            upstream_args=args_list,
            daemon_socket=daemon_socket,
            agent=agent,
        )
        mode_label = f"Daemon: {daemon_socket}"
    else:
        # Embedded Guard mode
        policy_path = Path(policy)
        if not policy_path.exists():
            console.print(f"[red]Policy file not found:[/red] {policy_path}")
            raise SystemExit(1)

        logger = SQLiteLogger(log_db) if log_db else None
        guard = Guard(policy=policy_path, logger=logger)

        proxy = MCPProxyServer(
            upstream_cmd=upstream_cmd,
            upstream_args=args_list,
            guard=guard,
            agent=agent,
        )
        mode_label = f"Policy: {policy_path.resolve()}"

    # Startup banner (to stderr, since stdout is the MCP protocol channel)
    banner = Text()
    banner.append("AvaKill MCP Proxy\n", style="bold green")
    banner.append(f"Mode:     {mode_label}\n", style="dim")
    banner.append(f"Agent:    {agent}\n", style="dim")
    banner.append(f"Upstream: {upstream_cmd} {upstream_args}\n", style="dim")
    if log_db:
        banner.append(f"Audit DB: {log_db}\n", style="dim")
    console.print(Panel(banner, border_style="green", padding=(0, 1)))

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(proxy.start())
