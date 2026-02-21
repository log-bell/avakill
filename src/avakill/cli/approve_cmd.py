"""AvaKill approve command — activate a proposed policy file."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.text import Text

from avakill.core.exceptions import ConfigError
from avakill.core.integrity import PolicyIntegrity
from avakill.core.policy import PolicyEngine


@click.command()
@click.argument("proposed_file")
@click.option(
    "--target",
    default=None,
    help="Target filename for the activated policy. Defaults to avakill.yaml.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip confirmation prompt.",
)
def approve(proposed_file: str, target: str | None, yes: bool) -> None:
    """Activate a proposed policy file.

    Validates the proposed policy, then copies it to the target location
    (default: avakill.yaml in the same directory).

    This command should only be run by humans, not by agents.
    Self-protection blocks agents from executing it.
    """
    console = Console()
    proposed_path = Path(proposed_file)

    if not proposed_path.exists():
        console.print(f"[red]File not found:[/red] {proposed_path}")
        raise SystemExit(1)

    # Validate the proposed policy
    try:
        raw = proposed_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        console.print(f"[red]Invalid YAML syntax:[/red] {exc}")
        raise SystemExit(1) from exc

    if not isinstance(data, dict):
        console.print("[red]Policy file must be a YAML mapping[/red]")
        raise SystemExit(1)

    try:
        engine = PolicyEngine.from_dict(data)
    except ConfigError as exc:
        console.print("[red]Policy validation failed:[/red]")
        console.print()
        cause = exc.__cause__
        if cause is not None and hasattr(cause, "errors"):
            for err in cause.errors():
                parts = []
                for p in err.get("loc", ()):
                    if isinstance(p, int):
                        parts.append(f"rule {p + 1}")
                    else:
                        parts.append(str(p))
                loc = " -> ".join(parts) if parts else "policy"
                msg = err.get("msg", str(err))
                console.print(f"  [yellow]{loc}[/yellow]: {msg}")
        else:
            console.print(f"  {exc.message}")
        console.print()
        console.print("[dim]Fix the errors, then run:[/dim]")
        console.print(f"  [bold]avakill review {proposed_file}[/bold]")
        raise SystemExit(1) from exc

    config = engine.config

    # Determine target path
    target_path = Path(target) if target else proposed_path.parent / "avakill.yaml"

    # Show summary
    console.print()
    summary = Text()
    summary.append("Source:  ")
    summary.append(str(proposed_path), style="cyan")
    summary.append("\nTarget:  ")
    summary.append(str(target_path), style="cyan")
    summary.append(f"\nRules:   {len(config.policies)}")
    summary.append(f"\nDefault: {config.default_action}")
    console.print(summary)
    console.print()

    # Confirm
    if not yes and not click.confirm("Activate this policy?"):
        console.print("[yellow]Aborted.[/yellow]")
        raise SystemExit(0)

    # Copy proposed to target
    if proposed_path.resolve() == target_path.resolve():
        console.print(f"[bold green]Policy already in place:[/bold green] {target_path}")
    else:
        # Backup existing target if it exists
        if target_path.exists():
            bak_path = target_path.with_suffix(target_path.suffix + ".bak")
            shutil.copy2(str(target_path), str(bak_path))
            console.print(f"[dim]Backup saved:[/dim] {bak_path}")

        # Atomic write: copy to temp file, then rename
        tmp_path = target_path.with_suffix(target_path.suffix + ".tmp")
        shutil.copy2(str(proposed_path), str(tmp_path))
        os.replace(str(tmp_path), str(target_path))
        console.print(f"[bold green]Policy activated:[/bold green] {target_path}")

    # Auto-sign if signing key is available
    key_hex = os.environ.get("AVAKILL_POLICY_KEY")
    if key_hex:
        try:
            key_bytes = bytes.fromhex(key_hex)
            sig_path = PolicyIntegrity.sign_file(target_path, key_bytes)
            console.print(f"[bold green]Auto-signed:[/bold green] {sig_path}")
        except (ValueError, OSError) as exc:
            console.print(f"[yellow]Warning: could not auto-sign:[/yellow] {exc}")
