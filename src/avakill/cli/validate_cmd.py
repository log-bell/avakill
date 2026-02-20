"""AvaKill validate command - validate a policy file."""

from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from avakill.core.exceptions import ConfigError
from avakill.core.integrity import PolicyIntegrity
from avakill.core.models import PolicyRule
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

    # Shadow detection
    shadow_warnings = _detect_shadowed_rules(config.policies)
    warnings.extend(shadow_warnings)

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

    # Show integrity status if signing key is available
    key_hex = os.environ.get("AVAKILL_POLICY_KEY")
    if key_hex:
        try:
            key_bytes = bytes.fromhex(key_hex)
            signed = PolicyIntegrity.verify_file(policy_path, key_bytes)
            if signed:
                console.print("[bold green]Signature: valid[/bold green]")
            else:
                sig_path = Path(str(policy_path) + ".sig")
                if sig_path.exists():
                    console.print("[bold red]Signature: INVALID[/bold red]")
                else:
                    console.print("[yellow]Signature: unsigned[/yellow]")
        except (ValueError, OSError):
            pass


def _detect_shadowed_rules(rules: list[PolicyRule]) -> list[str]:
    """Check for rules that shadow later rules with different actions.

    A rule R[i] shadows R[j] (j > i) if at least one tool name from R[j]
    also matches a pattern in R[i], and R[i] and R[j] have different actions.
    """
    warnings: list[str] = []

    # Collect all explicit tool names across all rules as test probes
    all_tool_names: set[str] = set()
    for rule in rules:
        for pattern in rule.tools:
            if "*" not in pattern and "?" not in pattern and pattern != "all":
                all_tool_names.add(pattern)

    for j in range(1, len(rules)):
        later = rules[j]
        for i in range(j):
            earlier = rules[i]
            if earlier.action == later.action:
                continue

            for tool in later.tools:
                if "*" in tool or "?" in tool or tool == "all":
                    # Glob in later rule: test known names that match it
                    for probe in all_tool_names:
                        if fnmatch(probe, tool) and _matches_rule(probe, earlier.tools):
                            warnings.append(
                                f"Rule {i + 1} '{earlier.name}' "
                                f"(tools: {', '.join(earlier.tools)}) "
                                f"shadows Rule {j + 1} "
                                f"'{later.name}' "
                                f"(tools: {', '.join(later.tools)}) "
                                f"\u2014 {probe} matches both. "
                                f"Rule {j + 1} may be unreachable "
                                f"for {probe} calls."
                            )
                            break
                else:
                    # Exact name: test against earlier patterns
                    if _matches_rule(tool, earlier.tools):
                        warnings.append(
                            f"Rule {i + 1} '{earlier.name}' "
                            f"(tools: {', '.join(earlier.tools)}) "
                            f"shadows Rule {j + 1} "
                            f"'{later.name}' "
                            f"(tools: {', '.join(later.tools)}) "
                            f"\u2014 {tool} matches both. "
                            f"Rule {j + 1} may be unreachable "
                            f"for {tool} calls."
                        )

    return warnings


def _matches_rule(tool_name: str, patterns: list[str]) -> bool:
    """Check if a tool name matches any pattern in a rule's tools list."""
    for pattern in patterns:
        if pattern in ("*", "all"):
            return True
        if fnmatch(tool_name, pattern):
            return True
    return False
