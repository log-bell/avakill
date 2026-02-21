"""AvaKill check-hardening command -- report hardening status of a policy file."""

from __future__ import annotations

import os
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


@click.command(name="check-hardening")
@click.argument("policy_file", required=False, default="avakill.yaml")
def check_hardening(policy_file: str) -> None:
    """Report hardening status of a policy file.

    Shows immutable flag status, file permissions, owner/group,
    signing configuration, and signature validity.
    """
    console = Console()
    path = Path(policy_file)

    if not path.exists():
        console.print(f"[red]Error:[/red] Policy file not found: {policy_file}")
        raise SystemExit(1)

    from avakill.hardening import check_file_permissions, check_immutable

    immutable = check_immutable(path)
    perms = check_file_permissions(path)

    # Check signing configuration
    signing_key_hex = os.environ.get("AVAKILL_POLICY_KEY")
    verify_key_hex = os.environ.get("AVAKILL_VERIFY_KEY")
    signing_configured = bool(signing_key_hex or verify_key_hex)

    sig_valid = False
    if signing_configured:
        from avakill.core.integrity import PolicyIntegrity

        try:
            key = bytes.fromhex(verify_key_hex or signing_key_hex)  # type: ignore[arg-type]
            sig_valid = PolicyIntegrity.verify_file(path, key)
        except Exception:
            sig_valid = False

    # Build status table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Check", style="bold", min_width=18)
    table.add_column("Status", min_width=12)
    table.add_column("Details")

    # Immutable flag
    if immutable:
        table.add_row("Immutable Flag", "[green]Set[/green]", "File is protected")
    else:
        table.add_row("Immutable Flag", "[red]Not Set[/red]", "Run: avakill harden")

    # File permissions
    table.add_row("Permissions", perms["mode"], f"uid={perms['uid']} gid={perms['gid']}")

    # World-writable check
    if perms["writable_by_others"]:
        table.add_row("World Writable", "[red]Yes[/red]", "File is writable by others!")
    else:
        table.add_row("World Writable", "[green]No[/green]", "")

    # Signing status
    if signing_configured:
        table.add_row("Signing", "[green]Configured[/green]", "Key available")
    else:
        table.add_row(
            "Signing",
            "[yellow]Not Configured[/yellow]",
            "Set AVAKILL_POLICY_KEY or AVAKILL_VERIFY_KEY",
        )

    # Signature validity
    if signing_configured:
        if sig_valid:
            table.add_row("Signature", "[green]Valid[/green]", "")
        else:
            table.add_row(
                "Signature",
                "[red]Invalid[/red]",
                "Signature missing or invalid",
            )
    else:
        table.add_row("Signature", "[dim]N/A[/dim]", "Signing not configured")

    # C-level audit hooks
    from avakill.core.audit_hooks import c_hooks_available

    if c_hooks_available():
        table.add_row(
            "C-Level Hooks",
            "[green]Active[/green]",
            "ctypes and gc introspection blocked",
        )
    else:
        table.add_row(
            "C-Level Hooks",
            "[yellow]Not Installed[/yellow]",
            "pipx inject avakill avakill\\[hardened]",
        )

    panel = Panel(
        table,
        title=f"Hardening Status: {policy_file}",
        border_style="blue",
    )
    console.print(panel)
