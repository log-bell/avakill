"""CLI commands for managing agent hook integrations."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table


@click.group()
def hook() -> None:
    """Manage agent hook integrations."""


@hook.command()
@click.option(
    "--agent",
    type=click.Choice(["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex", "all"]),
    required=True,
    help="Agent to install hook for.",
)
def install(agent: str) -> None:
    """Register AvaKill hook in an agent's configuration."""
    from avakill.hooks.installer import install_hook

    console = Console()
    agents = (
        ["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex"]
        if agent == "all"
        else [agent]
    )

    for a in agents:
        try:
            result = install_hook(a)
            console.print(
                f"[green]Installed[/green] hook for [bold]{a}[/bold] -> {result.config_path}"
            )
            console.print(f"  Command: [cyan]{result.command}[/cyan]")
            if result.smoke_test_passed is True:
                console.print("  Smoke test: [green]passed[/green]")
            elif result.smoke_test_passed is False:
                console.print("  Smoke test: [bold red]FAILED[/bold red]")
                console.print(
                    "  [bold red]The hook will NOT work.[/bold red] "
                    f"Verify that '{result.command}' is on PATH or reinstall avakill."
                )
            for warning in result.warnings:
                console.print(f"  [yellow]Warning:[/yellow] {warning}")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Failed[/red] to install hook for {a}: {exc}")

    # Warn about policy compatibility
    console.print()
    console.print(
        "[yellow]Important:[/yellow] The hook will evaluate tool calls against your AvaKill policy."
    )
    console.print(
        "  The [bold]default[/bold] template blocks tools not in its allowlist, "
        "which may lock out your agent."
    )
    console.print(
        "  For hooks, use the [bold]hooks[/bold] template: "
        "[cyan]avakill init --template hooks[/cyan]"
    )
    console.print(
        "  Or set [cyan]AVAKILL_POLICY[/cyan] to a policy file for standalone mode "
        "(no daemon required)."
    )


@hook.command()
@click.option(
    "--agent",
    type=click.Choice(["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex", "all"]),
    required=True,
    help="Agent to uninstall hook for.",
)
def uninstall(agent: str) -> None:
    """Remove AvaKill hook from an agent's configuration."""
    from avakill.hooks.installer import uninstall_hook

    console = Console()
    agents = (
        ["claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex"]
        if agent == "all"
        else [agent]
    )

    for a in agents:
        try:
            removed = uninstall_hook(a)
            if removed:
                console.print(f"[green]Removed[/green] hook for [bold]{a}[/bold]")
            else:
                console.print(f"[dim]No hook found for {a}[/dim]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Failed[/red] to uninstall hook for {a}: {exc}")


@hook.command(name="list")
def list_hooks() -> None:
    """Show detected agents and hook installation status."""
    from avakill.hooks.installer import detect_agents, list_installed_hooks

    console = Console()
    detected = detect_agents()
    installed = list_installed_hooks()

    table = Table(title="Agent Hook Status")
    table.add_column("Agent", style="bold")
    table.add_column("Detected")
    table.add_column("Hook Installed")

    for agent in ("claude-code", "gemini-cli", "cursor", "windsurf", "openai-codex"):
        is_detected = agent in detected
        is_installed = installed.get(agent, False)
        table.add_row(
            agent,
            "[green]yes[/green]" if is_detected else "[dim]no[/dim]",
            "[green]yes[/green]" if is_installed else "[dim]no[/dim]",
        )

    console.print(table)
