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
from avakill.mcp.proxy import MCPHTTPProxy, MCPProxyServer


@click.command("mcp-proxy")
@click.option(
    "--upstream-cmd",
    default=None,
    help="Stdio: command to run the upstream MCP server.",
)
@click.option(
    "--upstream-args",
    default="",
    help="Stdio: arguments for the upstream command (space-separated).",
)
@click.option(
    "--upstream-url",
    default=None,
    help="HTTP: URL of the upstream MCP server.",
)
@click.option(
    "--listen-port",
    default=5100,
    help="HTTP: local port to listen on.",
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
    upstream_cmd: str | None,
    upstream_args: str,
    upstream_url: str | None,
    listen_port: int,
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
    HTTP mode:
        avakill mcp-proxy --upstream-url http://localhost:3000/mcp --listen-port 5100

    \b
    Daemon mode:
        avakill mcp-proxy --upstream-cmd npx --upstream-args "..." --daemon ~/.avakill/avakill.sock
    """
    console = Console(stderr=True)

    if upstream_url:
        # HTTP proxy mode
        _run_http_proxy(upstream_url, listen_port, policy, daemon_socket, agent, log_db, console)
    elif upstream_cmd:
        # Stdio proxy mode
        _run_stdio_proxy(upstream_cmd, upstream_args, policy, daemon_socket, agent, log_db, console)
    else:
        console.print(
            "[red]Either --upstream-cmd (stdio) or --upstream-url (HTTP) is required.[/red]"
        )
        raise SystemExit(1)


def _run_stdio_proxy(
    upstream_cmd: str,
    upstream_args: str,
    policy: str,
    daemon_socket: str | None,
    agent: str,
    log_db: str | None,
    console: Console,
) -> None:
    """Start the stdio-based MCP proxy."""
    args_list = shlex.split(upstream_args) if upstream_args else []

    if daemon_socket:
        proxy = MCPProxyServer(
            upstream_cmd=upstream_cmd,
            upstream_args=args_list,
            daemon_socket=daemon_socket,
            agent=agent,
        )
        mode_label = f"Daemon: {daemon_socket}"
    else:
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

    banner = Text()
    banner.append("AvaKill MCP Proxy (stdio)\n", style="bold green")
    banner.append(f"Mode:     {mode_label}\n", style="dim")
    banner.append(f"Agent:    {agent}\n", style="dim")
    banner.append(f"Upstream: {upstream_cmd} {upstream_args}\n", style="dim")
    if log_db:
        banner.append(f"Audit DB: {log_db}\n", style="dim")
    console.print(Panel(banner, border_style="green", padding=(0, 1)))

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(proxy.start())


def _run_http_proxy(
    upstream_url: str,
    listen_port: int,
    policy: str,
    daemon_socket: str | None,
    agent: str,
    log_db: str | None,
    console: Console,
) -> None:
    """Start the HTTP-based MCP proxy."""
    if daemon_socket:
        http_proxy = MCPHTTPProxy(
            upstream_url=upstream_url,
            daemon_socket=daemon_socket,
            port=listen_port,
        )
        mode_label = f"Daemon: {daemon_socket}"
    else:
        policy_path = Path(policy)
        if not policy_path.exists():
            console.print(f"[red]Policy file not found:[/red] {policy_path}")
            raise SystemExit(1)

        logger = SQLiteLogger(log_db) if log_db else None
        guard = Guard(policy=policy_path, logger=logger)

        http_proxy = MCPHTTPProxy(
            upstream_url=upstream_url,
            guard=guard,
            port=listen_port,
        )
        mode_label = f"Policy: {policy_path.resolve()}"

    banner = Text()
    banner.append("AvaKill MCP Proxy (HTTP)\n", style="bold green")
    banner.append(f"Mode:     {mode_label}\n", style="dim")
    banner.append(f"Agent:    {agent}\n", style="dim")
    banner.append(f"Upstream: {upstream_url}\n", style="dim")
    banner.append(f"Listen:   http://127.0.0.1:{listen_port}\n", style="dim")
    if log_db:
        banner.append(f"Audit DB: {log_db}\n", style="dim")
    console.print(Panel(banner, border_style="green", padding=(0, 1)))

    async def _run() -> None:
        await http_proxy.start()
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await http_proxy.stop()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run())
