"""AvaKill verify command -- verify a policy file's HMAC signature."""

from __future__ import annotations

import os
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from avakill.core.integrity import FileSnapshot, PolicyIntegrity


@click.command()
@click.argument("policy_file")
@click.option("--key", default=None, help="Hex-encoded 32-byte signing key.")
@click.option("--verbose", "-v", is_flag=True, help="Show full file metadata.")
def verify(policy_file: str, key: str | None, verbose: bool) -> None:
    """Verify a policy file's HMAC-SHA256 signature.

    Checks the .sig sidecar file against the policy contents.
    """
    console = Console()

    key_hex = key or os.environ.get("AVAKILL_POLICY_KEY")
    if not key_hex:
        console.print(
            "[red]Error:[/red] No signing key. "
            "Set AVAKILL_POLICY_KEY or pass --key."
        )
        raise SystemExit(1)

    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError as exc:
        console.print("[red]Error:[/red] Invalid hex key.")
        raise SystemExit(1) from exc

    policy_path = Path(policy_file)
    if not policy_path.exists():
        console.print(f"[red]File not found:[/red] {policy_path}")
        raise SystemExit(1)

    sig_path = Path(str(policy_path) + ".sig")
    if not sig_path.exists():
        console.print(f"[red]Signature not found:[/red] {sig_path}")
        console.print(f"Sign it first with: [bold]avakill sign {policy_file}[/bold]")
        raise SystemExit(1)

    valid = PolicyIntegrity.verify_file(policy_path, key_bytes)

    if valid:
        console.print(f"[bold green]Valid signature:[/bold green] {policy_path}")
    else:
        console.print(f"[bold red]Invalid signature:[/bold red] {policy_path}")
        console.print("[red]The policy file or signature has been tampered with.[/red]")

    if verbose:
        try:
            snap = FileSnapshot.from_path(str(policy_path))
            info = Text()
            info.append(f"Path:     {snap.path}\n")
            info.append(f"SHA-256:  {snap.sha256}\n")
            info.append(f"Size:     {snap.size} bytes\n")
            info.append(f"Mode:     {oct(snap.mode)}\n")
            info.append(f"Inode:    {snap.inode}\n")
            info.append(f"UID/GID:  {snap.uid}/{snap.gid}\n")
            console.print(Panel(info, title="File Metadata", border_style="blue"))
        except OSError as exc:
            console.print(f"[yellow]Could not read metadata:[/yellow] {exc}")

    if not valid:
        raise SystemExit(1)
