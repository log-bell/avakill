"""AvaKill sign command -- cryptographically sign a policy file."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import click
import yaml
from rich.console import Console

from avakill.core.exceptions import ConfigError
from avakill.core.integrity import PolicyIntegrity
from avakill.core.policy import PolicyEngine


@click.command()
@click.argument("policy_file", required=False)
@click.option("--key", default=None, help="Hex-encoded 32-byte signing key.")
@click.option(
    "--generate-key",
    is_flag=True,
    default=False,
    help="Generate a new signing key and print it.",
)
@click.option(
    "--ed25519",
    is_flag=True,
    default=False,
    help="Use Ed25519 signing (requires PyNaCl and AVAKILL_SIGNING_KEY).",
)
def sign(
    policy_file: str | None,
    key: str | None,
    generate_key: bool,
    ed25519: bool,
) -> None:
    """Sign a policy file with HMAC-SHA256 or Ed25519.

    Creates a .sig sidecar file alongside the policy.
    The signing key can be passed via --key or env vars:
    AVAKILL_POLICY_KEY for HMAC, AVAKILL_SIGNING_KEY for Ed25519.
    """
    console = Console()

    if generate_key:
        new_key = secrets.token_hex(32)
        click.echo(f"export AVAKILL_POLICY_KEY={new_key}")
        return

    if policy_file is None:
        console.print("[red]Error:[/red] POLICY_FILE argument is required (or use --generate-key)")
        raise SystemExit(1)

    # Resolve signing key
    if ed25519:
        key_hex = key or os.environ.get("AVAKILL_SIGNING_KEY")
        key_env_name = "AVAKILL_SIGNING_KEY"
    else:
        key_hex = key or os.environ.get("AVAKILL_POLICY_KEY")
        key_env_name = "AVAKILL_POLICY_KEY"

    if not key_hex:
        if ed25519:
            console.print(
                "[red]Error:[/red] No signing key. "
                f"Set {key_env_name} or pass --key.\n"
                "Generate a keypair with: [bold]avakill keygen[/bold]"
            )
        else:
            console.print(
                "[red]Error:[/red] No signing key. "
                f"Set {key_env_name} or pass --key.\n"
                "Generate one with: [bold]avakill sign --generate-key[/bold]"
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

    # Validate policy before signing
    try:
        raw = policy_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        console.print(f"[red]Invalid YAML:[/red] {exc}")
        raise SystemExit(1) from exc

    if not isinstance(data, dict):
        console.print("[red]Policy file must be a YAML mapping[/red]")
        raise SystemExit(1)

    try:
        PolicyEngine.from_dict(data)
    except ConfigError as exc:
        console.print(f"[red]Invalid policy:[/red] {exc.message}")
        raise SystemExit(1) from exc

    # Sign it
    if ed25519:
        try:
            sig_path = PolicyIntegrity.sign_file_ed25519(policy_path, key_bytes)
        except RuntimeError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise SystemExit(1) from exc
        sig_type = "Ed25519"
    else:
        sig_path = PolicyIntegrity.sign_file(policy_path, key_bytes)
        sig_type = "HMAC-SHA256"

    sig_content = sig_path.read_text().strip()
    console.print(f"[bold green]Signed ({sig_type}):[/bold green] {policy_path}")
    console.print(f"  Signature: {sig_content[:24]}...")
    console.print(f"  Sidecar:   {sig_path}")
    console.print()
    console.print(f"Verify with: [bold]avakill verify {policy_file}[/bold]")
