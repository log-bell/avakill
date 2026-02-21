"""AvaKill keygen command -- generate Ed25519 keypair for policy signing."""

from __future__ import annotations

import click
from rich.console import Console


@click.command()
def keygen() -> None:
    """Generate an Ed25519 keypair for policy signing.

    Prints export commands for AVAKILL_SIGNING_KEY (private, hex)
    and AVAKILL_VERIFY_KEY (public, hex).
    """
    console = Console()

    try:
        from nacl.signing import SigningKey
    except ImportError as exc:
        console.print(
            "[red]Error:[/red] PyNaCl is required for Ed25519 key generation.\n"
            "Install with: [bold]pipx inject avakill PyNaCl[/bold]"
        )
        raise SystemExit(1) from exc

    sk = SigningKey.generate()
    private_hex = sk.encode().hex()
    public_hex = sk.verify_key.encode().hex()

    click.echo(f"export AVAKILL_SIGNING_KEY={private_hex}")
    click.echo(f"export AVAKILL_VERIFY_KEY={public_hex}")

    console.print()
    console.print("[bold green]Ed25519 keypair generated.[/bold green]")
    console.print("  [bold]AVAKILL_SIGNING_KEY[/bold] — keep private, use for signing")
    console.print("  [bold]AVAKILL_VERIFY_KEY[/bold]  — deploy with agent, use for verification")
    console.print()
    console.print("Sign a policy: [bold]avakill sign --ed25519 policy.yaml[/bold]")
    console.print("Verify:        [bold]avakill verify policy.yaml[/bold]")
