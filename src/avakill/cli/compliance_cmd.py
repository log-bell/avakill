"""Compliance assessment and reporting CLI commands."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from avakill.compliance.assessor import ComplianceAssessor
from avakill.compliance.frameworks import FRAMEWORKS
from avakill.compliance.reporter import ComplianceReporter
from avakill.core.engine import Guard

console = Console()

_FRAMEWORK_CHOICES = list(FRAMEWORKS.keys()) + ["all"]


@click.group()
def compliance() -> None:
    """Compliance assessment and reporting."""


@compliance.command()
@click.option(
    "--framework",
    type=click.Choice(_FRAMEWORK_CHOICES),
    default="all",
    help="Compliance framework to assess against.",
)
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    help="Output format.",
)
@click.option("--output", "-o", default=None, help="Write report to file.")
def report(framework: str, policy: str, fmt: str, output: str | None) -> None:
    """Generate a compliance assessment report."""
    policy_path = Path(policy)
    if not policy_path.exists():
        console.print(f"[red]Policy file not found:[/] {policy}")
        raise SystemExit(1)

    try:
        guard = Guard(policy=policy_path, self_protection=True)
    except Exception as exc:
        console.print(f"[red]Failed to load policy:[/] {exc}")
        raise SystemExit(1) from exc

    assessor = ComplianceAssessor(guard)
    reporter = ComplianceReporter()

    if framework == "all":
        reports = assessor.assess_all()
    else:
        reports = {framework: assessor.assess(framework)}

    output_parts: list[str] = []

    for _fw, rpt in reports.items():
        if fmt == "table":
            table = reporter.to_rich_table(rpt)
            if output is None:
                console.print(table)
                console.print(f"\n[bold]{rpt.summary}[/]\n")
            else:
                # For file output, fall back to markdown
                output_parts.append(reporter.to_markdown(rpt))
        elif fmt == "json":
            json_str = reporter.to_json(rpt)
            if output is None:
                click.echo(json_str)
            else:
                output_parts.append(json_str)
        elif fmt == "markdown":
            md = reporter.to_markdown(rpt)
            if output is None:
                click.echo(md)
            else:
                output_parts.append(md)

    if output is not None and output_parts:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(output_parts))
        console.print(f"[green]Report written to {output}[/]")


@compliance.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
def gaps(policy: str) -> None:
    """Show compliance gaps with remediation steps."""
    policy_path = Path(policy)
    if not policy_path.exists():
        console.print(f"[red]Policy file not found:[/] {policy}")
        raise SystemExit(1)

    try:
        guard = Guard(policy=policy_path, self_protection=True)
    except Exception as exc:
        console.print(f"[red]Failed to load policy:[/] {exc}")
        raise SystemExit(1) from exc

    assessor = ComplianceAssessor(guard)
    reports = assessor.assess_all()

    has_gaps = False
    for fw, rpt in reports.items():
        failing = [c for c in rpt.controls if c.status in ("fail", "partial")]
        if not failing:
            continue
        has_gaps = True
        console.print(f"\n[bold red]{fw}[/] — {len(failing)} gap(s):")
        for ctrl in failing:
            status_color = "red" if ctrl.status == "fail" else "yellow"
            console.print(
                f"  [{status_color}]{ctrl.status.upper()}[/] {ctrl.control_id}: {ctrl.title}"
            )
            for rec in ctrl.recommendations:
                console.print(f"    → {rec}")

    if not has_gaps:
        console.print("[green]No compliance gaps found.[/]")
