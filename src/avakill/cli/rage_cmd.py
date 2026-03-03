"""Toggle rage mode for AvaKill denial messages."""

from __future__ import annotations

import click


@click.command()
@click.argument("state", type=click.Choice(["on", "off", "status"]))
def rage(state: str) -> None:
    """Toggle rage mode on or off.

    Rage mode adds humorous denial messages to blocked tool calls.
    """
    from avakill.cli.config import get_config, set_rage_mode

    if state == "status":
        enabled = get_config().get("rage_mode", False)
        icon = "\U0001f52a" if enabled else "\U0001f610"
        label = "ON" if enabled else "OFF"
        click.echo(f"  {icon} Rage mode: {label}")
        return

    enabled = state == "on"
    set_rage_mode(enabled)
    if enabled:
        click.echo("  \U0001f52a Rage mode ON. Denial messages are now... colorful.")
    else:
        click.echo("  \U0001f610 Rage mode OFF. Back to boring professional messages.")
