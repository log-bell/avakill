"""AvaKill quickstart command - guided onboarding flow."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console

from avakill.hooks.installer import detect_agents, install_hook

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_LEVEL_TO_TEMPLATE: dict[str, str] = {
    "strict": "strict",
    "moderate": "default",
    "permissive": "hooks",
}


@click.command()
@click.option(
    "--agent",
    default=None,
    help='Agent to guard (e.g. "claude-code", "cursor", "all", "none").',
)
@click.option(
    "--level",
    type=click.Choice(["strict", "moderate", "permissive"]),
    default=None,
    help="Protection level.",
)
@click.option(
    "--scan/--no-scan",
    default=None,
    help="Scan project directory for sensitive files.",
)
@click.option(
    "--output",
    default="avakill.yaml",
    help="Output path for the generated policy file.",
)
def quickstart(agent: str | None, level: str | None, scan: bool | None, output: str) -> None:
    """Guided setup for AvaKill — detect agents, generate policy, install hooks."""
    console = Console()
    is_interactive = sys.stdin.isatty()

    console.print()
    console.print("[bold]AvaKill Quickstart[/bold]")
    console.print("\u2500" * 31)

    # Step 1: Detect agents
    detected_agents = detect_agents()
    if detected_agents:
        console.print(f"Detected agents: [cyan]{', '.join(detected_agents)}[/cyan]")

    # Step 2: Choose agent
    if agent is None:
        if not is_interactive:
            raise click.UsageError("--agent is required in non-interactive mode")
        choices = detected_agents + ["all", "none"]
        if not detected_agents:
            choices = ["none"]
        from rich.prompt import Prompt

        agent = Prompt.ask(
            "Which agent do you want to guard?",
            choices=choices,
            default=detected_agents[0] if detected_agents else "none",
            console=console,
        )

    # Step 3: Choose protection level
    if level is None:
        if not is_interactive:
            raise click.UsageError("--level is required in non-interactive mode")
        from rich.prompt import Prompt

        level = Prompt.ask(
            "What protection level?",
            choices=["strict", "moderate", "permissive"],
            default="moderate",
            console=console,
        )

    # Step 4: Scan?
    if scan is None:
        if not is_interactive:
            scan = False
        else:
            from rich.prompt import Prompt

            scan_answer = Prompt.ask(
                "Scan this directory for sensitive files?",
                choices=["y", "n"],
                default="y",
                console=console,
            )
            scan = scan_answer == "y"

    # Step 5: Generate policy
    output_path = Path(output)
    template_name = _LEVEL_TO_TEMPLATE[level]
    src = _TEMPLATES_DIR / f"{template_name}.yaml"
    if not src.exists():
        raise click.ClickException(f"Template not found: {src}")

    shutil.copy2(src, output_path)

    # Merge scan rules if requested
    scan_results = []
    if scan:
        from avakill.cli.scanner import (
            detect_project_type,
            detect_sensitive_files,
            generate_scan_rules,
        )

        sensitive_files = detect_sensitive_files(Path.cwd())
        project_types = detect_project_type(Path.cwd())
        scan_rules = generate_scan_rules(sensitive_files, project_types)
        scan_results = sensitive_files

        if scan_results:
            file_names = [sf.path for sf in scan_results]
            console.print(f"Detected sensitive files: [yellow]{', '.join(file_names)}[/yellow]")

        if scan_rules:
            policy_data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
            existing_rules = policy_data.get("policies", [])
            policy_data["policies"] = scan_rules + existing_rules
            output_path.write_text(
                yaml.dump(policy_data, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )

    console.print()

    # Step 6: Validate
    policy_data = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    rule_count = len(policy_data.get("policies", []))
    try:
        from avakill.core.policy import PolicyEngine

        PolicyEngine.from_dict(policy_data)
        console.print(
            f"[green]\u2713[/green] Policy generated: "
            f"[cyan]{output_path}[/cyan] ({rule_count} rules)"
        )
        console.print("[green]\u2713[/green] Validation passed")
    except Exception as exc:
        console.print(f"[red]\u2717[/red] Validation failed: {exc}")
        raise SystemExit(1) from exc

    # Step 7: Install hook
    agents_to_install: list[str] = []
    if agent and agent != "none":
        agents_to_install = detected_agents if agent == "all" else [agent]

    for a in agents_to_install:
        try:
            result = install_hook(a)
            console.print(f"[green]\u2713[/green] Hook installed for [cyan]{a}[/cyan]")
            for w in result.warnings:
                console.print(f"  [yellow]Warning:[/yellow] {w}")
        except KeyError:
            console.print(f"[yellow]![/yellow] Unknown agent: {a} (skipping hook install)")

    # Step 8: Next steps
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("  1. Review your policy:  [cyan]avakill review[/cyan]")
    console.print(
        "  2. Test a tool call:    "
        "[cyan]avakill evaluate --tool shell_exec "
        '--args \'{"command": "rm -rf /"}\'[/cyan]'
    )
    console.print(f"  3. Approve the policy:  [cyan]avakill approve {output_path}[/cyan]")
    console.print()
