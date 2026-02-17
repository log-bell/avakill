"""AvaKill review command — inspect a proposed policy before activation."""

from __future__ import annotations

from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from avakill.core.exceptions import ConfigError
from avakill.core.policy import PolicyEngine


@click.command()
@click.argument("proposed_file")
def review(proposed_file: str) -> None:
    """Review a proposed policy file before activation.

    Validates the YAML, shows a syntax-highlighted view and rules summary,
    then prints the 'avakill approve' command to activate it.

    Exits 0 if valid, 1 if invalid.
    """
    console = Console()
    proposed_path = Path(proposed_file)

    if not proposed_path.exists():
        console.print(f"[red]File not found:[/red] {proposed_path}")
        raise SystemExit(1)

    # Check YAML syntax
    try:
        raw = proposed_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        console.print(f"[red]Invalid YAML syntax:[/red] {exc}")
        raise SystemExit(1) from exc

    if not isinstance(data, dict):
        console.print("[red]Policy file must be a YAML mapping[/red]")
        raise SystemExit(1)

    # Validate against schema
    try:
        engine = PolicyEngine.from_dict(data)
    except ConfigError as exc:
        console.print(f"[red]Policy validation failed:[/red]\n{exc.message}")
        raise SystemExit(1) from exc

    config = engine.config

    # Show syntax-highlighted YAML
    console.print()
    syntax = Syntax(raw, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title=f"Proposed Policy: {proposed_path.name}", border_style="blue"))
    console.print()

    # Rules summary table
    table = Table(title="Rules Summary", expand=True, show_lines=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Name", style="cyan", min_width=20)
    table.add_column("Tools", min_width=20)
    table.add_column("Action", width=18)

    for i, rule in enumerate(config.policies, 1):
        tools_str = ", ".join(rule.tools)
        action_style = {
            "allow": "green",
            "deny": "red",
            "require_approval": "yellow",
        }.get(rule.action, "white")
        action_text = Text(rule.action, style=action_style)
        table.add_row(str(i), rule.name, tools_str, action_text)

    console.print(table)
    console.print()

    # Summary
    summary = Text()
    summary.append(f"Version:        {config.version}\n")
    summary.append("Default action: ")
    da_style = "green" if config.default_action == "allow" else "red"
    summary.append(f"{config.default_action}\n", style=da_style)
    summary.append(f"Total rules:    {len(config.policies)}\n")

    console.print(Panel(summary, title="Policy Summary", border_style="green", padding=(0, 2)))
    console.print()

    # Show approval command
    console.print("[bold green]Policy is valid.[/bold green]")
    console.print()
    console.print("To activate this policy, run:")
    console.print(f"  [bold]avakill approve {proposed_file}[/bold]")
