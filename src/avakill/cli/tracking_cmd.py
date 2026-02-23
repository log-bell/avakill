"""AvaKill tracking — user-facing interface for activity tracking.

Wraps the daemon lifecycle with user-friendly language.
The word 'daemon' never appears in user-facing output.
"""

from __future__ import annotations

import contextlib
import os
import signal
import sys
from pathlib import Path

import click
from rich.console import Console


@click.group()
def tracking() -> None:
    """Manage activity tracking (logs, diagnostics, dashboard)."""


@tracking.command()
def on() -> None:
    """Enable activity tracking."""
    from avakill.cli.config import get_audit_db_path, set_tracking
    from avakill.daemon.server import DaemonServer

    console = Console()

    # Already running?
    running, pid = DaemonServer.is_running()
    if running:
        set_tracking(True)
        console.print()
        console.print(f"  Activity tracking is already running (PID {pid}).")
        console.print()
        return

    # Discover policy
    policy_path = _find_policy()
    if policy_path is None:
        console.print()
        console.print("  [red]No policy file found.[/red] Run [cyan]avakill setup[/cyan] first.")
        console.print()
        raise SystemExit(1)

    # Start the daemon
    audit_db = get_audit_db_path()
    audit_db_expanded = str(Path(audit_db).expanduser())
    pid = _start_background(str(policy_path), audit_db_expanded)

    if pid is None:
        console.print()
        console.print("  [red]Failed to start activity tracking.[/red]")
        console.print(
            "  Try running in foreground for details: [cyan]avakill daemon start -f[/cyan]"
        )
        console.print()
        raise SystemExit(1)

    set_tracking(True)

    db_display = audit_db.replace(str(Path.home()), "~")
    console.print()
    console.print(f"  [green]\u2713[/green] Activity tracking enabled (PID {pid})")
    console.print(f"    Logs: [dim]{db_display}[/dim]")
    console.print()


@tracking.command()
def off() -> None:
    """Disable activity tracking."""
    from avakill.cli.config import get_audit_db_path, set_tracking
    from avakill.daemon.server import DaemonServer

    console = Console()

    running, pid = DaemonServer.is_running()
    if not running:
        set_tracking(False)
        console.print()
        console.print("  Activity tracking is not running.")
        console.print()
        return

    # Stop the daemon
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGTERM)

    set_tracking(False)

    db_path = get_audit_db_path()
    db_display = db_path.replace(str(Path.home()), "~")
    console.print()
    console.print("  [green]\u2713[/green] Activity tracking stopped.")
    console.print(f"    Your audit history is preserved at [dim]{db_display}[/dim]")
    console.print()


@tracking.command()
def status() -> None:
    """Show activity tracking status."""
    from avakill.cli.config import get_audit_db_path, is_tracking_enabled
    from avakill.daemon.server import DaemonServer

    console = Console()

    running, pid = DaemonServer.is_running()
    enabled = is_tracking_enabled()

    console.print()
    if running:
        console.print("  [bold]Activity tracking:[/bold] [green]enabled[/green]")
        console.print(f"    PID:       {pid}")

        # Uptime from PID file mtime
        pid_path = DaemonServer.default_pid_path()
        uptime_str = _format_uptime(pid_path)
        if uptime_str:
            console.print(f"    Uptime:    {uptime_str}")

        # Audit DB stats
        audit_db = get_audit_db_path()
        db_path = Path(audit_db).expanduser()
        db_display = audit_db.replace(str(Path.home()), "~")
        if db_path.exists():
            stats = _db_stats(db_path)
            console.print(f"    Audit DB:  {db_display} ({stats})")
        else:
            console.print(f"    Audit DB:  {db_display}")

        # Policy
        policy = _find_policy()
        if policy:
            console.print(f"    Policy:    {policy}")
    elif enabled:
        console.print("  [bold]Activity tracking:[/bold] [yellow]not running[/yellow]")
        console.print()
        console.print("    Activity tracking was previously enabled but is not currently running.")
        console.print()
        console.print("    Restart it:  [cyan]avakill tracking on[/cyan]")
    else:
        console.print("  [bold]Activity tracking:[/bold] off")
        console.print()
        console.print("    Enable it:  [cyan]avakill tracking on[/cyan]")

    console.print()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _find_policy() -> Path | None:
    """Find a policy file via env var or cascade discovery."""
    env = os.environ.get("AVAKILL_POLICY")
    if env:
        p = Path(env).expanduser()
        return p if p.is_file() else None

    from avakill.core.cascade import PolicyCascade

    cascade = PolicyCascade()
    discovered = cascade.discover()
    if discovered:
        return discovered[-1][1]  # most local
    return None


def _start_background(policy: str, log_db: str) -> int | None:
    """Start the daemon as a background process. Returns PID or None."""
    import subprocess
    import time

    cmd = [
        sys.executable,
        "-m",
        "avakill",
        "daemon",
        "start",
        "--foreground",
        "--policy",
        policy,
        "--log-db",
        log_db,
    ]

    popen_kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = 0x00000008 | 0x08000000
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **popen_kwargs)
    time.sleep(1.0)

    exit_code = proc.poll()
    if exit_code is not None:
        if proc.stderr:
            proc.stderr.close()
        return None

    if proc.stderr:
        proc.stderr.close()
    return proc.pid


def _format_uptime(pid_path: Path) -> str | None:
    """Format uptime from PID file modification time."""
    import time

    try:
        mtime = pid_path.stat().st_mtime
        elapsed = int(time.time() - mtime)
        if elapsed < 60:
            return f"{elapsed}s"
        if elapsed < 3600:
            return f"{elapsed // 60}m {elapsed % 60}s"
        hours = elapsed // 3600
        mins = (elapsed % 3600) // 60
        return f"{hours}h {mins}m"
    except OSError:
        return None


def _db_stats(db_path: Path) -> str:
    """Return a brief stats string for an audit DB."""
    import sqlite3

    size_mb = db_path.stat().st_size / (1024 * 1024)
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT COUNT(*) FROM audit_events")
        count = cursor.fetchone()[0]
        conn.close()
        if size_mb >= 1:
            return f"{count:,} events, {size_mb:.1f} MB"
        return f"{count:,} events"
    except Exception:
        if size_mb >= 1:
            return f"{size_mb:.1f} MB"
        return "empty"
