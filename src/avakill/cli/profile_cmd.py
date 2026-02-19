"""CLI commands for managing agent containment profiles."""

from __future__ import annotations

import click


@click.group()
def profile() -> None:
    """Manage agent containment profiles."""


@profile.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Show descriptions.")
def list_cmd(verbose: bool) -> None:
    """List available agent profiles."""
    from rich.console import Console
    from rich.table import Table

    from avakill.profiles.loader import list_profiles, load_profile

    console = Console()
    names = list_profiles()

    if not names:
        console.print("[dim]No built-in profiles found.[/dim]")
        return

    table = Table(title="Agent Profiles")
    table.add_column("Name", style="cyan")
    table.add_column("Hooks", justify="center")
    table.add_column("MCP", justify="center")

    if verbose:
        table.add_column("Description")

    for name in names:
        p = load_profile(name)
        hooks = "yes" if p.agent.supports_hooks else "no"
        mcp = "yes" if p.agent.mcp_native else "no"
        row: list[str] = [p.agent.display_name or name, hooks, mcp]
        if verbose:
            row.append(p.agent.description or "")
        table.add_row(*row)

    console.print(table)


@profile.command("show")
@click.argument("name")
def show_cmd(name: str) -> None:
    """Show details of an agent profile."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    from avakill.profiles.loader import load_profile

    console = Console()

    try:
        p = load_profile(name)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1) from None

    lines: list[str] = []
    lines.append(f"[bold]{p.agent.display_name or p.agent.name}[/bold]")
    if p.agent.description:
        lines.append(f"[dim]{p.agent.description}[/dim]")
    lines.append("")

    # Protection modes
    lines.append("[bold cyan]Protection modes:[/bold cyan]")
    lines.append(f"  Hooks support: {'yes' if p.agent.supports_hooks else 'no'}")
    lines.append(f"  MCP native: {'yes' if p.agent.mcp_native else 'no'}")
    if p.agent.command:
        lines.append(f"  Default command: {' '.join(p.agent.command)}")
    lines.append("")

    # Detection
    if p.agent.detect_paths or p.agent.detect_commands:
        lines.append("[bold cyan]Detection:[/bold cyan]")
        for dp in p.agent.detect_paths:
            lines.append(f"  path: {dp}")
        for dc in p.agent.detect_commands:
            lines.append(f"  command: {dc}")
        lines.append("")

    # Sandbox config
    sb = p.sandbox
    lines.append("[bold cyan]Sandbox:[/bold cyan]")
    if sb.allow_paths.read:
        lines.append(f"  Read: {', '.join(sb.allow_paths.read)}")
    if sb.allow_paths.write:
        lines.append(f"  Write: {', '.join(sb.allow_paths.write)}")
    if sb.allow_paths.execute:
        lines.append(f"  Execute: {', '.join(sb.allow_paths.execute)}")
    if sb.allow_network.connect:
        lines.append(f"  Network connect: {', '.join(sb.allow_network.connect)}")
    if sb.allow_network.bind:
        lines.append(f"  Network bind: {', '.join(sb.allow_network.bind)}")

    rl = sb.resource_limits
    if rl.max_memory_mb or rl.max_processes or rl.timeout_seconds:
        lines.append("")
        lines.append("[bold cyan]Resource limits:[/bold cyan]")
        if rl.max_memory_mb:
            lines.append(f"  Memory: {rl.max_memory_mb} MB")
        if rl.max_processes:
            lines.append(f"  Processes: {rl.max_processes}")
        if rl.timeout_seconds:
            lines.append(f"  Timeout: {rl.timeout_seconds}s")

    body = Text.from_markup("\n".join(lines))
    console.print(Panel(body, title=f"Profile: {name}", border_style="cyan"))
