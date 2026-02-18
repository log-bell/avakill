"""CLI commands for managing the AvaKill daemon."""

from __future__ import annotations

import os
import sys

import click


@click.group()
def daemon() -> None:
    """Manage the AvaKill daemon."""


@daemon.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--socket", default=None, help="Unix socket path.")
@click.option("--log-db", default=None, help="SQLite audit log path.")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize).")
def start(policy: str, socket: str | None, log_db: str | None, foreground: bool) -> None:
    """Start the AvaKill daemon."""
    import asyncio
    from pathlib import Path

    from avakill.daemon.server import DaemonServer

    policy_path = Path(policy)
    if not policy_path.exists():
        click.echo(f"Error: policy file not found: {policy}", err=True)
        raise SystemExit(1)

    running, pid = DaemonServer.is_running()
    if running:
        click.echo(f"Daemon already running (PID {pid}).")
        raise SystemExit(1)

    from avakill.core.engine import Guard

    kwargs: dict = {"policy": str(policy_path)}
    if log_db:
        from avakill.logging.sqlite_logger import SQLiteLogger

        kwargs["logger"] = SQLiteLogger(log_db)

    guard = Guard(**kwargs)

    server_kwargs: dict = {}
    if socket:
        server_kwargs["socket_path"] = socket

    server = DaemonServer(guard, **server_kwargs)

    if foreground:
        click.echo(f"Starting AvaKill daemon in foreground (policy: {policy})...")
        asyncio.run(server.serve_forever())
    else:
        click.echo(f"Starting AvaKill daemon (policy: {policy})...")
        _daemonize(server)


@daemon.command()
@click.option("--socket", default=None, help="Unix socket path (to find PID file).")
def stop(socket: str | None) -> None:
    """Stop the running daemon."""
    import signal

    from avakill.daemon.server import DaemonServer

    pid_file = None
    if socket:
        # Derive pid_file from socket path convention
        from pathlib import Path

        pid_file = str(Path(socket).with_suffix(".pid"))

    running, pid = DaemonServer.is_running(pid_file=pid_file)
    if not running or pid is None:
        click.echo("No running daemon found.")
        raise SystemExit(1)

    os.kill(pid, signal.SIGTERM)
    click.echo(f"Sent SIGTERM to daemon (PID {pid}).")


@daemon.command()
@click.option("--socket", default=None, help="Unix socket path.")
def status(socket: str | None) -> None:
    """Show daemon status."""
    from avakill.daemon.server import DaemonServer

    pid_file = None
    if socket:
        from pathlib import Path

        pid_file = str(Path(socket).with_suffix(".pid"))

    running, pid = DaemonServer.is_running(pid_file=pid_file)
    if running:
        sock_path = socket or str(DaemonServer.default_socket_path())
        click.echo(f"Daemon is running (PID {pid}).")
        click.echo(f"Socket: {sock_path}")
    else:
        click.echo("Daemon is not running.")


def _daemonize(server: object) -> None:
    """Fork into background and run the daemon server."""
    import asyncio

    pid = os.fork()
    if pid > 0:
        # Parent — report and exit
        click.echo(f"Daemon started (PID {pid}).")
        sys.exit(0)

    # Child — new session, run server
    os.setsid()

    # Redirect stdio to /dev/null
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    os.close(devnull)

    asyncio.run(server.serve_forever())  # type: ignore[attr-defined]
