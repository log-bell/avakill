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
        console.print("[red]Policy validation failed:[/red]")
        console.print()
        cause = exc.__cause__
        if cause is not None and hasattr(cause, "errors"):
            for err in cause.errors():
                parts = []
                for p in err.get("loc", ()):
                    if isinstance(p, int):
                        parts.append(f"rule {p + 1}")
                    else:
                        parts.append(str(p))
                loc = " -> ".join(parts) if parts else "policy"
                msg = err.get("msg", str(err))
                console.print(f"  [yellow]{loc}[/yellow]: {msg}")
        else:
            console.print(f"  {exc.message}")
        console.print()
        console.print("[dim]Fix the errors above, then run:[/dim]")
        console.print(f"  [bold]avakill review {proposed_file}[/bold]")
        raise SystemExit(1) from exc

    config = engine.config

    # Show syntax-highlighted YAML
    console.print()
    syntax = Syntax(raw, "yaml", theme="monokai", line_numbers=True)
    panel_title = f"Proposed Policy: {proposed_path.name}"
    console.print(Panel(syntax, title=panel_title, border_style="blue"))
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

    # Show approval command and next steps
    console.print("[bold green]Policy is valid.[/bold green]")
    console.print()
    next_steps = Table.grid(padding=(0, 2))
    next_steps.add_column(style="bold cyan", min_width=16)
    next_steps.add_column()
    next_steps.add_row("Activate", f"avakill approve {proposed_file}")
    next_steps.add_row(
        "Test a rule",
        f'avakill evaluate --policy {proposed_file} --tool Bash --args \'{{"cmd": "ls"}}\'',
    )
    next_steps.add_row("Compare active", "avakill validate")
    next_steps.add_row("Edit proposed", str(proposed_path.resolve()))
    console.print(Panel(next_steps, title="What's next?", border_style="dim", padding=(1, 2)))
