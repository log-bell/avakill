"""AvaKill reset — factory-reset that reverses everything setup does.

Stops the daemon, uninstalls hooks, unwraps MCP configs, and deletes
~/.avakill/. Policy file is preserved by default.

This is a human-only command — self-protection blocks agents from running it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import sys
from pathlib import Path

import click
from rich.console import Console


@click.command()
@click.option("--confirm", is_flag=True, help="Skip interactive prompt (for scripted use).")
@click.option(
    "--include-policy",
    is_flag=True,
    help="Also delete avakill.yaml/avakill.yml in the current directory.",
)
@click.option("--keep-hooks", is_flag=True, help="Skip hook uninstallation.")
def reset(confirm: bool, include_policy: bool, keep_hooks: bool) -> None:
    """Factory-reset AvaKill — reverses everything setup does.

    Stops the daemon, uninstalls hooks, unwraps MCP configs, and removes
    ~/.avakill/. Policy file is preserved unless --include-policy is used.
    """
    console = Console()

    # ------------------------------------------------------------------
    # TTY gate
    # ------------------------------------------------------------------
    if not confirm and not sys.stdin.isatty():
        click.echo(
            "avakill reset requires an interactive terminal.\n"
            "\n"
            "For scripted use:\n"
            "  avakill reset --confirm",
            err=True,
        )
        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------
    avakill_dir = Path.home() / ".avakill"
    daemon_running, daemon_pid = _check_daemon()
    installed_hooks = _check_hooks()
    wrapped_mcp = _check_mcp_wraps()
    avakill_dir_exists = avakill_dir.is_dir()
    policy_files = _find_policy_files()

    # ------------------------------------------------------------------
    # Display summary
    # ------------------------------------------------------------------
    console.print()
    console.print("  [bold]AvaKill Reset[/bold]")
    console.print()
    console.print("  The following will be removed:")
    console.print()

    has_anything = False

    if daemon_running:
        console.print(f"    \u2022 Stop daemon (PID {daemon_pid})")
        has_anything = True

    if installed_hooks and not keep_hooks:
        for agent in installed_hooks:
            console.print(f"    \u2022 Uninstall hook: {agent}")
        has_anything = True

    if wrapped_mcp:
        for config_path in wrapped_mcp:
            display = str(config_path).replace(str(Path.home()), "~")
            console.print(f"    \u2022 Unwrap MCP config: {display}")
        has_anything = True

    if avakill_dir_exists:
        display = str(avakill_dir).replace(str(Path.home()), "~")
        console.print(f"    \u2022 Delete {display}/")
        has_anything = True

    if include_policy and policy_files:
        for pf in policy_files:
            console.print(f"    \u2022 Delete {pf.name}")
        has_anything = True

    if not has_anything:
        console.print("    [dim]Nothing to clean up — AvaKill is not installed.[/dim]")
        console.print()
        return

    console.print()

    # ------------------------------------------------------------------
    # Confirm
    # ------------------------------------------------------------------
    if not confirm:
        console.print("  Type [bold]reset[/bold] to confirm, or anything else to abort.")
        console.print()
        answer = click.prompt("  ", default="", show_default=False)
        if answer.strip() != "reset":
            console.print()
            console.print("  [dim]Aborted.[/dim]")
            console.print()
            raise SystemExit(0)
        console.print()

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------

    # 1. Stop daemon
    if daemon_running and daemon_pid is not None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(daemon_pid, signal.SIGTERM)
        console.print("  [green]\u2713[/green] Stopped daemon")

    # 2. Uninstall hooks
    if installed_hooks and not keep_hooks:
        from avakill.hooks.installer import uninstall_hook

        for agent in installed_hooks:
            try:
                uninstall_hook(agent)
                console.print(f"  [green]\u2713[/green] Uninstalled hook: {agent}")
            except (KeyError, Exception) as exc:
                console.print(f"  [yellow]\u26a0[/yellow] Could not uninstall {agent}: {exc}")

    # 3. Unwrap MCP configs
    if wrapped_mcp:
        from avakill.mcp.wrapper import unwrap_mcp_config, write_mcp_config

        for mcp_config in wrapped_mcp:
            try:
                unwrapped = unwrap_mcp_config(mcp_config)
                write_mcp_config(unwrapped)
                display = str(mcp_config.path).replace(str(Path.home()), "~")
                console.print(f"  [green]\u2713[/green] Unwrapped MCP config: {display}")
            except Exception as exc:
                console.print(f"  [yellow]\u26a0[/yellow] Could not unwrap MCP config: {exc}")

    # 4. Delete ~/.avakill/
    if avakill_dir_exists:
        shutil.rmtree(avakill_dir)
        display = str(avakill_dir).replace(str(Path.home()), "~")
        console.print(f"  [green]\u2713[/green] Deleted {display}/")

    # 5. Delete policy files
    if include_policy and policy_files:
        for pf in policy_files:
            pf.unlink()
            console.print(f"  [green]\u2713[/green] Deleted {pf.name}")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    console.print()
    console.print("  [bold]Reset complete.[/bold]")
    console.print()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _check_daemon() -> tuple[bool, int | None]:
    """Check if the daemon is running."""
    try:
        from avakill.daemon.server import DaemonServer

        return DaemonServer.is_running()
    except Exception:
        return False, None


def _check_hooks() -> list[str]:
    """Return list of agents with AvaKill hooks installed."""
    try:
        from avakill.hooks.installer import list_installed_hooks

        status = list_installed_hooks()
        return [agent for agent, installed in status.items() if installed]
    except Exception:
        return []


def _check_mcp_wraps() -> list:
    """Return list of MCPConfig objects that have wrapped servers."""
    try:
        from avakill.mcp.config import discover_mcp_configs, is_already_wrapped

        configs = discover_mcp_configs()
        wrapped = []
        for config in configs:
            if any(is_already_wrapped(server) for server in config.servers):
                wrapped.append(config)
        return wrapped
    except Exception:
        return []


def _find_policy_files() -> list[Path]:
    """Find policy files in the current directory."""
    found = []
    for name in ("avakill.yaml", "avakill.yml"):
        p = Path.cwd() / name
        if p.is_file():
            found.append(p)
    return found
