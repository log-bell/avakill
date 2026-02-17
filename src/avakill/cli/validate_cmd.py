"""AvaKill validate command - validate a policy file."""

from __future__ import annotations

from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from avakill.core.exceptions import ConfigError
from avakill.core.policy import PolicyEngine


@click.command()
@click.argument("policy_file", default="avakill.yaml")
def validate(policy_file: str) -> None:
    """Validate a policy file.

    Loads the YAML, checks all rules for correctness, and prints a summary.
    Exits 0 if valid, 1 if invalid (for CI use).
    """
    console = Console()
    policy_path = Path(policy_file)

    if not policy_path.exists():
        console.print(f"[red]File not found:[/red] {policy_path}")
        raise SystemExit(1)

    # First check: valid YAML syntax
    try:
        raw = policy_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        console.print(f"[red]Invalid YAML syntax:[/red] {exc}")
        raise SystemExit(1) from exc

    if not isinstance(data, dict):
        console.print("[red]Policy file must be a YAML mapping[/red]")
        raise SystemExit(1)

    # Second check: validate against schema
    try:
        engine = PolicyEngine.from_dict(data)
    except ConfigError as exc:
        console.print(f"[red]Policy validation failed:[/red]\n{exc.message}")
        raise SystemExit(1) from exc

    config = engine.config

    # Build summary table
    table = Table(title="Policy Rules", expand=True, show_lines=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Name", style="cyan", min_width=20)
    table.add_column("Tools", min_width=20)
    table.add_column("Action", width=18)
    table.add_column("Conditions", min_width=14)
    table.add_column("Rate Limit", width=14)

    warnings: list[str] = []

    for i, rule in enumerate(config.policies, 1):
        tools_str = ", ".join(rule.tools)
        action_style = {
            "allow": "green",
            "deny": "red",
            "require_approval": "yellow",
        }.get(rule.action, "white")
        action_text = Text(rule.action, style=action_style)

        # Conditions summary
        cond_parts: list[str] = []
        if rule.conditions:
            if rule.conditions.args_match:
                for k, v in rule.conditions.args_match.items():
                    cond_parts.append(f"{k} ~ {v}")
            if rule.conditions.args_not_match:
                for k, v in rule.conditions.args_not_match.items():
                    cond_parts.append(f"{k} !~ {v}")
        cond_str = "; ".join(cond_parts) if cond_parts else "-"

        # Rate limit summary
        rl_str = f"{rule.rate_limit.max_calls}/{rule.rate_limit.window}" if rule.rate_limit else "-"

        table.add_row(str(i), rule.name, tools_str, action_text, cond_str, rl_str)

        # Warnings
        if ("all" in rule.tools or "*" in rule.tools) and rule.action == "deny":
            warnings.append(
                f"Rule '{rule.name}' denies ALL tools - "
                "ensure it's positioned correctly (rules are first-match-wins)"
            )
        if not rule.log:
            warnings.append(f"Rule '{rule.name}' has logging disabled")

    console.print()
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

    if warnings:
        console.print()
        for w in warnings:
            console.print(f"[yellow]  Warning:[/yellow] {w}")
        console.print()

    console.print("[bold green]Policy is valid.[/bold green]")
