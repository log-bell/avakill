"""AvaKill mcp-wrap and mcp-unwrap commands.

Rewrite agent MCP configs to route all tool calls through AvaKill's
policy engine, or restore the original configs.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from avakill.mcp.config import discover_mcp_configs, is_already_wrapped
from avakill.mcp.wrapper import unwrap_mcp_config, wrap_mcp_config, write_mcp_config

_AGENT_CHOICES = ["claude-desktop", "cursor", "windsurf", "cline", "continue", "openclaw", "all"]


@click.command("mcp-wrap")
@click.option(
    "--agent",
    type=click.Choice(_AGENT_CHOICES),
    default="all",
    help="Which agent to wrap (default: all detected).",
)
@click.option("--policy", default="avakill.yaml", help="Path to the policy file.")
@click.option("--daemon", is_flag=True, help="Use daemon mode instead of embedded Guard.")
@click.option("--dry-run", is_flag=True, help="Show changes without writing.")
@click.option("--test", is_flag=True, help="Run avakill-shim --diagnose after wrapping.")
def mcp_wrap(agent: str, policy: str, daemon: bool, dry_run: bool, test: bool) -> None:
    """Wrap MCP server configs to route through AvaKill.

    Rewrites agent MCP configs so all tool calls pass through AvaKill's
    policy engine. Creates a backup of the original config.

    \b
    Examples:
        avakill mcp-wrap --agent claude-desktop --policy hardened.yaml
        avakill mcp-wrap --agent all --daemon
        avakill mcp-wrap --dry-run
    """
    console = Console()
    agent_filter = None if agent == "all" else agent

    configs = discover_mcp_configs(agent=agent_filter)
    if not configs:
        console.print("[yellow]No MCP configs found.[/yellow]")
        raise SystemExit(0)

    for config in configs:
        wrapped = wrap_mcp_config(config, policy=policy, daemon=daemon)

        # Show changes
        table = Table(title=f"{config.agent} — {config.config_path}")
        table.add_column("Server", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Command")

        for orig, new in zip(config.servers, wrapped.servers, strict=False):
            if is_already_wrapped(orig):
                table.add_row(orig.name, "already wrapped", orig.command)
            elif orig.transport != "stdio":
                table.add_row(orig.name, "skipped (non-stdio)", orig.command)
            else:
                table.add_row(
                    new.name,
                    "wrapped",
                    f"avakill mcp-proxy ... --upstream-cmd {orig.command}",
                )
        console.print(table)

        if not dry_run:
            write_mcp_config(wrapped)
            console.print(f"[green]Config updated: {config.config_path}[/green]")
        else:
            console.print("[dim]Dry run — no changes written.[/dim]")

    if test and not dry_run:
        _run_diagnose(console)


def _run_diagnose(console: Console) -> None:
    """Run avakill-shim --diagnose to validate the wrapping."""
    import json
    import shutil
    import subprocess

    shim = shutil.which("avakill-shim")
    if not shim:
        console.print("[yellow]avakill-shim not found in PATH — skipping diagnose.[/yellow]")
        return

    try:
        result = subprocess.run(
            [shim, "--diagnose", "--upstream-cmd", "echo"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        try:
            output = json.loads(result.stdout)
            for check in output.get("checks", []):
                status = check.get("status", "")
                style = {"ok": "green", "warn": "yellow", "fail": "red"}.get(status, "dim")
                console.print(
                    f"  [{style}]{check.get('check', '?')}: {status}[/{style}]"
                    f" — {check.get('detail', '')}"
                )
        except json.JSONDecodeError:
            console.print(f"[dim]{result.stdout}[/dim]")
    except FileNotFoundError:
        console.print("[yellow]avakill-shim not found.[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("[yellow]avakill-shim --diagnose timed out.[/yellow]")


@click.command("mcp-unwrap")
@click.option(
    "--agent",
    type=click.Choice(_AGENT_CHOICES),
    default="all",
    help="Which agent to unwrap (default: all detected).",
)
def mcp_unwrap(agent: str) -> None:
    """Restore original MCP server configs (undo mcp-wrap).

    Reverses the wrapping done by ``mcp-wrap``, restoring the original
    server commands. Creates a backup before writing.
    """
    console = Console()
    agent_filter = None if agent == "all" else agent

    configs = discover_mcp_configs(agent=agent_filter)
    if not configs:
        console.print("[yellow]No MCP configs found.[/yellow]")
        raise SystemExit(0)

    for config in configs:
        has_wrapped = any(is_already_wrapped(s) for s in config.servers)
        if not has_wrapped:
            console.print(f"[dim]{config.agent}: no wrapped servers found.[/dim]")
            continue

        unwrapped = unwrap_mcp_config(config)
        write_mcp_config(unwrapped)
        console.print(f"[green]{config.agent}: config restored ({config.config_path})[/green]")
