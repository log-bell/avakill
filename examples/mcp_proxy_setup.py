"""AvaKill MCP Proxy — protect any MCP server transparently.

Demonstrates:
  1. How the MCP proxy intercepts tools/call requests
  2. Simulating requests through the proxy (tools/list passes, tools/call is filtered)
  3. Generating the correct claude_desktop_config.json snippet

No MCP server needed — uses in-process simulation.

Usage:
    python examples/mcp_proxy_setup.py
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from avakill import Guard
from avakill.mcp.proxy import MCPProxyServer

console = Console()
POLICY_PATH = Path(__file__).parent / "demo_policy.yaml"


# ---------------------------------------------------------------------------
# Simulated MCP requests
# ---------------------------------------------------------------------------


REQUESTS = [
    {
        "label": "initialize (handshake)",
        "message": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}},
        },
    },
    {
        "label": "tools/list (enumerate tools)",
        "message": {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        },
    },
    {
        "label": "tools/call: search_users (safe read)",
        "message": {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search_users",
                "arguments": {"query": "active premium"},
            },
        },
    },
    {
        "label": "tools/call: execute_sql SELECT (safe SQL)",
        "message": {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "execute_sql",
                "arguments": {"query": "SELECT * FROM users LIMIT 10"},
            },
        },
    },
    {
        "label": "tools/call: execute_sql DROP TABLE (destructive!)",
        "message": {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "execute_sql",
                "arguments": {"query": "DROP TABLE users CASCADE"},
            },
        },
    },
    {
        "label": "tools/call: shell_execute rm -rf (dangerous!)",
        "message": {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "shell_execute",
                "arguments": {"command": "rm -rf /important/data"},
            },
        },
    },
    {
        "label": "tools/call: delete_database (destructive!)",
        "message": {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "delete_database",
                "arguments": {"name": "production"},
            },
        },
    },
    {
        "label": "tools/call: shell_execute ls (safe shell)",
        "message": {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "shell_execute",
                "arguments": {"command": "ls -la /tmp"},
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Demo: simulate proxy interception
# ---------------------------------------------------------------------------


async def demo_proxy_interception() -> None:
    """Show how the proxy evaluates each MCP request."""
    console.print(
        Panel(
            "[bold]MCP Proxy Interception Demo[/]\n"
            "The proxy sits between the MCP client (Claude Desktop, Cursor, etc.)\n"
            "and the upstream MCP server. Only tools/call is intercepted.\n"
            "All other methods pass through unchanged.",
            title="How It Works",
            border_style="blue",
        )
    )

    guard = Guard(policy=POLICY_PATH)
    proxy = MCPProxyServer(upstream_cmd="echo", upstream_args=[], guard=guard)

    table = Table(title="MCP Request Interception", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Request", style="cyan", max_width=45)
    table.add_column("Action", justify="center")
    table.add_column("Detail", style="yellow", max_width=40)

    for req in REQUESTS:
        msg = req["message"]
        req_id = msg.get("id", "?")

        result = await proxy._handle_client_message(msg)

        if result is None:
            # Passed through (forwarded to upstream)
            method = msg.get("method", "")
            if method == "tools/call":
                action = "[bold green]FORWARD[/]"
                detail = "Allowed by policy"
            else:
                action = "[green]PASSTHROUGH[/]"
                detail = f"Not a tools/call ({method})"
        else:
            action = "[bold red]BLOCKED[/]"
            detail = result["result"]["content"][0]["text"][:40]

        table.add_row(str(req_id), req["label"], action, detail)

    console.print(table)


# ---------------------------------------------------------------------------
# Config generator
# ---------------------------------------------------------------------------


def generate_config_snippet() -> None:
    """Generate claude_desktop_config.json snippet for the MCP proxy."""
    console.print(
        Panel(
            "[bold]Claude Desktop Configuration[/]\n"
            "Add this to your claude_desktop_config.json to protect\n"
            "an MCP server with AvaKill.",
            title="Configuration",
            border_style="green",
        )
    )

    # Before: direct connection
    before = {
        "mcpServers": {
            "database": {
                "command": "python",
                "args": ["db_server.py"],
            }
        }
    }

    console.print("\n  [bold]Before[/] (unprotected):")
    console.print(
        Syntax(
            json.dumps(before, indent=2),
            "json",
            theme="monokai",
            padding=1,
        )
    )

    # After: AvaKill proxy in front
    after = {
        "mcpServers": {
            "database": {
                "command": "avakill",
                "args": [
                    "mcp-proxy",
                    "--upstream-cmd",
                    "python",
                    "--upstream-args",
                    "db_server.py",
                    "--policy",
                    "avakill.yaml",
                ],
            }
        }
    }

    console.print("\n  [bold]After[/] (protected by AvaKill):")
    console.print(
        Syntax(
            json.dumps(after, indent=2),
            "json",
            theme="monokai",
            padding=1,
        )
    )

    # Multi-server example
    multi = {
        "mcpServers": {
            "database": {
                "command": "avakill",
                "args": [
                    "mcp-proxy",
                    "--upstream-cmd",
                    "python",
                    "--upstream-args",
                    "db_server.py",
                    "--policy",
                    "strict_db.yaml",
                ],
            },
            "filesystem": {
                "command": "avakill",
                "args": [
                    "mcp-proxy",
                    "--upstream-cmd",
                    "npx",
                    "--upstream-args",
                    "@anthropic/mcp-server-filesystem /home/user/safe-dir",
                    "--policy",
                    "fs_policy.yaml",
                ],
            },
        }
    }

    console.print("\n  [bold]Multi-server[/] (each with its own policy):")
    console.print(
        Syntax(
            json.dumps(multi, indent=2),
            "json",
            theme="monokai",
            padding=1,
        )
    )


# ---------------------------------------------------------------------------
# Full relay simulation
# ---------------------------------------------------------------------------


class _MockStreamWriter:
    """Collects written bytes for inspection."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    async def drain(self) -> None:
        pass

    def get_messages(self) -> list[dict]:
        messages = []
        for line in self._buffer.decode("utf-8").split("\n"):
            line = line.strip()
            if line:
                messages.append(json.loads(line))
        return messages


async def demo_full_relay() -> None:
    """Drive the proxy's run() method with simulated streams."""
    console.print(
        Panel(
            "[bold]Full Relay Simulation[/]\n"
            "Sends multiple MCP messages through the proxy's relay loop.\n"
            "Shows what the upstream receives vs. what the client gets back.",
            title="Relay",
            border_style="magenta",
        )
    )

    guard = Guard(policy=POLICY_PATH)
    proxy = MCPProxyServer("echo", [], guard)

    # Build client input stream
    client_reader = asyncio.StreamReader()
    client_writer = _MockStreamWriter()
    upstream_reader = asyncio.StreamReader()
    upstream_writer = _MockStreamWriter()

    # Feed all requests to the client reader
    for req in REQUESTS:
        data = json.dumps(req["message"]) + "\n"
        client_reader.feed_data(data.encode())
    client_reader.feed_eof()

    # Simulate upstream responses for forwarded requests
    for req in REQUESTS:
        msg = req["message"]
        method = msg.get("method", "")
        if method != "tools/call":
            # Non-tool methods: upstream would respond
            resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": True}}
            upstream_reader.feed_data((json.dumps(resp) + "\n").encode())
    upstream_reader.feed_eof()

    await proxy.run(client_reader, client_writer, upstream_reader, upstream_writer)

    # Analyze results
    forwarded = upstream_writer.get_messages()
    client_msgs = client_writer.get_messages()

    console.print(f"\n  Messages forwarded to upstream: [green]{len(forwarded)}[/]")
    for msg in forwarded:
        method = msg.get("method", "response")
        params = msg.get("params", {})
        name = params.get("name", "")
        label = f"{method}" + (f" ({name})" if name else "")
        console.print(f"    [green]>>>[/] {label}")

    blocked = [m for m in client_msgs if m.get("result", {}).get("isError")]
    passed = [m for m in client_msgs if not m.get("result", {}).get("isError")]

    console.print(f"\n  Blocked responses sent to client: [red]{len(blocked)}[/]")
    for msg in blocked:
        text = msg["result"]["content"][0]["text"][:60]
        console.print(f"    [red]<<<[/] id={msg['id']}: {text}")

    console.print(f"\n  Pass-through responses to client: [green]{len(passed)}[/]")
    for msg in passed:
        console.print(f"    [green]<<<[/] id={msg['id']}: ok")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    console.print(
        Panel.fit(
            "[bold]AvaKill MCP Proxy Demo[/]",
            border_style="bright_blue",
        )
    )

    asyncio.run(_async_main())


async def _async_main() -> None:
    await demo_proxy_interception()
    console.print()
    generate_config_snippet()
    console.print()
    await demo_full_relay()


if __name__ == "__main__":
    main()
