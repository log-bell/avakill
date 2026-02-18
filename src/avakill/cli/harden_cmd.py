"""AvaKill harden command -- apply OS-level hardening to policy files."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console


@click.command()
@click.argument("policy_file", required=False, default="avakill.yaml")
@click.option(
    "--chattr",
    "use_chattr",
    is_flag=True,
    default=False,
    help="Set Linux immutable flag (chattr +i). Requires root.",
)
@click.option(
    "--schg",
    "use_schg",
    is_flag=True,
    default=False,
    help="Set macOS system immutable flag (chflags schg). Requires root.",
)
@click.option(
    "--selinux",
    "use_selinux",
    is_flag=True,
    default=False,
    help="Output SELinux type enforcement template.",
)
@click.option(
    "--apparmor",
    "use_apparmor",
    is_flag=True,
    default=False,
    help="Output AppArmor profile template.",
)
@click.option(
    "--seccomp",
    "use_seccomp",
    is_flag=True,
    default=False,
    help="Output seccomp-bpf profile JSON.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(),
    help="Write template output to file instead of stdout.",
)
def harden(
    policy_file: str,
    use_chattr: bool,
    use_schg: bool,
    use_selinux: bool,
    use_apparmor: bool,
    use_seccomp: bool,
    output: str | None,
) -> None:
    """Apply OS-level hardening to a policy file.

    Sets immutable flags or outputs security templates (SELinux, AppArmor, seccomp).
    Auto-detects platform when no specific flag is given.
    """
    console = Console()

    # Template output (no policy file needed)
    if use_selinux:
        _output_template("selinux.te", output, console)
        return
    if use_apparmor:
        _output_template("apparmor.profile", output, console)
        return
    if use_seccomp:
        _output_template("seccomp.json", output, console)
        return

    # Auto-detect platform if no immutable flag specified
    if not use_chattr and not use_schg:
        if sys.platform == "linux":
            use_chattr = True
        elif sys.platform == "darwin":
            use_schg = True
        else:
            console.print(f"[red]Error:[/red] Unsupported platform: {sys.platform}")
            console.print("Use --selinux, --apparmor, or --seccomp for template output.")
            raise SystemExit(1)

    # Validate policy file exists
    path = Path(policy_file)
    if not path.exists():
        console.print(f"[red]Error:[/red] Policy file not found: {policy_file}")
        raise SystemExit(1)

    # Check root privileges
    if sys.platform == "win32":
        console.print("[red]Error:[/red] Immutable file flags are not supported on Windows.")
        console.print("Use --selinux, --apparmor, or --seccomp for template output.")
        raise SystemExit(1)

    if os.geteuid() != 0:
        flag = "--chattr" if use_chattr else "--schg"
        console.print("[red]Error:[/red] Setting immutable flag requires root privileges.")
        console.print(f"Run with: [bold]sudo avakill harden {flag} {policy_file}[/bold]")
        raise SystemExit(1)

    # Apply hardening
    from avakill import hardening

    try:
        if use_chattr:
            if sys.platform != "linux":
                console.print("[red]Error:[/red] --chattr is only supported on Linux.")
                raise SystemExit(1)
            hardening.set_immutable_linux(path)
            console.print(f"[bold green]Hardened:[/bold green] {path}")
            console.print("  Immutable flag set (chattr +i)")
            console.print(f"  Remove with: [bold]sudo chattr -i {path}[/bold]")
        elif use_schg:
            if sys.platform != "darwin":
                console.print("[red]Error:[/red] --schg is only supported on macOS.")
                raise SystemExit(1)
            hardening.set_immutable_macos(path)
            console.print(f"[bold green]Hardened:[/bold green] {path}")
            console.print("  System immutable flag set (chflags schg)")
            console.print(f"  Remove with: [bold]sudo chflags noschg {path}[/bold]")
    except SystemExit:
        raise
    except Exception as exc:
        console.print(f"[red]Error:[/red] Failed to set immutable flag: {exc}")
        raise SystemExit(1) from exc


def _output_template(
    template_name: str, output_path: str | None, console: Console
) -> None:
    """Output a hardening template to stdout or a file."""
    from avakill.hardening import get_template_content

    try:
        content = get_template_content(template_name)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Template not found: {template_name}")
        raise SystemExit(1) from None

    if output_path:
        Path(output_path).write_text(content)
        console.print(f"[bold green]Written:[/bold green] {output_path}")
    else:
        click.echo(content)
