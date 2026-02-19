"""CLI commands for OS-level enforcement."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from avakill.core.policy import load_policy

console = Console()


@click.group()
def enforce() -> None:
    """OS-level enforcement commands.

    Generate or apply OS-level security restrictions derived from
    AvaKill policy deny rules. Supports Linux Landlock, macOS
    sandbox-exec, Windows Job Objects, and Cilium Tetragon.
    """


@enforce.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--dry-run", is_flag=True, help="Show ruleset without applying.")
def landlock(policy: str, dry_run: bool) -> None:
    """Apply Landlock restrictions (Linux 5.13+).

    Translates deny rules into Landlock filesystem access restrictions.
    Once applied, restrictions cannot be removed for the process lifetime.
    """
    from avakill.enforcement.landlock import LandlockEnforcer

    enforcer = LandlockEnforcer()

    if not enforcer.available():
        console.print(
            "[bold red]Error:[/] Landlock is not available on this system. "
            "Requires Linux 5.13+ with Landlock support.",
        )
        raise SystemExit(1)

    try:
        engine = load_policy(policy)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1) from exc

    config = engine.config
    ruleset = enforcer.generate_ruleset(config)

    if dry_run:
        console.print("[bold]Landlock Ruleset (dry run):[/]")
        console.print(f"  ABI version: {ruleset['landlock_abi']}")
        console.print(f"  Handled access flags: {ruleset['handled_access_fs']:#x}")
        console.print(f"  Restricted operations: {', '.join(ruleset['restricted_flag_names'])}")
        console.print()
        for source in ruleset["sources"]:
            console.print(
                f"  Rule [bold]{source['rule']}[/] "
                f"(tool: {source['tool_pattern']}): "
                f"{', '.join(source['flag_names'])}"
            )
        return

    enforcer.apply(config)
    console.print("[bold green]Landlock restrictions applied.[/]")


@enforce.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--output", "-o", required=True, help="Output path for SBPL profile.")
def sandbox(policy: str, output: str) -> None:
    """Generate macOS sandbox-exec profile.

    Produces a Sandbox Profile Language (SBPL) file from deny rules.
    Use with: sandbox-exec -f <profile> <command>
    """
    from avakill.enforcement.sandbox_exec import SandboxExecEnforcer

    enforcer = SandboxExecEnforcer()

    if not enforcer.available():
        console.print(
            "[bold red]Error:[/] sandbox-exec is only available on macOS.",
        )
        raise SystemExit(1)

    try:
        engine = load_policy(policy)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1) from exc

    config = engine.config
    result = enforcer.write_profile(config, Path(output))
    console.print(f"[bold green]Sandbox profile written to:[/] {result}")


@enforce.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--dry-run", is_flag=True, help="Show restrictions without applying.")
def windows(policy: str, dry_run: bool) -> None:
    """Apply Windows process restrictions.

    Creates a Job Object with child-process limits and removes dangerous
    token privileges (SeRestorePrivilege, SeBackupPrivilege, etc.).
    Privilege removal is irreversible for the process lifetime.
    """
    from avakill.enforcement.windows import WindowsEnforcer

    enforcer = WindowsEnforcer()

    if not enforcer.available():
        console.print(
            "[bold red]Error:[/] Windows enforcement is only available on Windows.",
        )
        raise SystemExit(1)

    try:
        engine = load_policy(policy)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1) from exc

    config = engine.config
    report = enforcer.generate_report(config)

    if dry_run:
        console.print("[bold]Windows Enforcement Report (dry run):[/]")
        console.print(f"  Job Object: {'yes' if report['job_object'] else 'no'}")
        console.print(
            f"  Privileges to remove: {', '.join(report['privileges_removed']) or '(none)'}"
        )
        console.print()
        for source in report["sources"]:
            console.print(
                f"  Rule [bold]{source['rule']}[/] "
                f"(tool: {source['tool_pattern']}): "
                f"{', '.join(source['actions'])}"
            )
        return

    enforcer.apply(config)
    console.print("[bold green]Windows restrictions applied.[/]")


@enforce.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--output", "-o", required=True, help="Output path for TracingPolicy YAML.")
def tetragon(policy: str, output: str) -> None:
    """Generate Cilium Tetragon TracingPolicy YAML.

    Produces a TracingPolicy resource for kernel-level enforcement
    via Cilium Tetragon. Deploy with: kubectl apply -f <output>
    """
    from avakill.enforcement.tetragon import TetragonPolicyGenerator

    generator = TetragonPolicyGenerator()

    try:
        engine = load_policy(policy)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(1) from exc

    config = engine.config
    result = generator.write(config, Path(output))
    console.print(f"[bold green]Tetragon TracingPolicy written to:[/] {result}")
