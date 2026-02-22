"""CLI commands for managing the AvaKill daemon."""

from __future__ import annotations

import os
import signal
import sys

import click


@click.group()
def daemon() -> None:
    """Manage the AvaKill daemon."""


@daemon.command()
@click.option("--policy", default="avakill.yaml", help="Path to policy file.")
@click.option("--socket", default=None, help="Unix socket path (ignored on Windows).")
@click.option("--tcp-port", default=None, type=int, help="TCP port for daemon.")
@click.option("--log-db", default=None, help="SQLite audit log path.")
@click.option(
    "--approval-db",
    default="~/.avakill/approvals.db",
    help="Approval request database path.",
)
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize).")
@click.option("--enforce", is_flag=True, help="Apply OS-level enforcement (Landlock/sandbox-exec).")
def start(
    policy: str,
    socket: str | None,
    tcp_port: int | None,
    log_db: str | None,
    approval_db: str,
    foreground: bool,
    enforce: bool,
) -> None:
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

    from avakill.core.approval import ApprovalStore
    from avakill.core.engine import Guard

    kwargs: dict = {"policy": str(policy_path)}
    if log_db:
        from avakill.logging.sqlite_logger import SQLiteLogger

        kwargs["logger"] = SQLiteLogger(log_db)

    kwargs["approval_store"] = ApprovalStore(approval_db)
    guard = Guard(**kwargs)

    server_kwargs: dict = {}
    if socket and sys.platform != "win32":
        server_kwargs["socket_path"] = socket
    if tcp_port is not None:
        server_kwargs["tcp_port"] = tcp_port

    if foreground:
        server_kwargs["on_ready"] = lambda addr: click.echo(f"Listening on {addr}")

    server = DaemonServer(guard, os_enforce=enforce, **server_kwargs)

    if foreground:
        click.echo(f"Starting AvaKill daemon in foreground (policy: {policy})...")
        asyncio.run(server.serve_forever())
    else:
        click.echo(f"Starting AvaKill daemon (policy: {policy})...")
        _daemonize(policy, socket, tcp_port, log_db, approval_db=approval_db, enforce=enforce)


@daemon.command()
@click.option("--socket", default=None, help="Unix socket path (to find PID file).")
@click.option("--tcp-port", default=None, type=int, help="TCP port.")
def stop(socket: str | None, tcp_port: int | None) -> None:
    """Stop the running daemon."""
    from avakill.daemon.server import DaemonServer

    pid_file = None
    if socket:
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
@click.option("--tcp-port", default=None, type=int, help="TCP port.")
def status(socket: str | None, tcp_port: int | None) -> None:
    """Show daemon status."""
    from avakill.daemon.server import DaemonServer
    from avakill.daemon.transport import DEFAULT_TCP_PORT, _default_port_file

    pid_file = None
    if socket:
        from pathlib import Path

        pid_file = str(Path(socket).with_suffix(".pid"))

    running, pid = DaemonServer.is_running(pid_file=pid_file)
    if running:
        click.echo(f"Daemon is running (PID {pid}).")
        if sys.platform == "win32" or tcp_port is not None:
            port_file = _default_port_file()
            if port_file.exists():
                port = port_file.read_text().strip()
                click.echo(f"Listening: 127.0.0.1:{port}")
            else:
                click.echo(f"Listening: 127.0.0.1:{tcp_port or DEFAULT_TCP_PORT}")
        else:
            sock_path = socket or str(DaemonServer.default_socket_path())
            click.echo(f"Socket: {sock_path}")
    else:
        click.echo("Daemon is not running.")


def _daemonize(
    policy: str,
    socket: str | None,
    tcp_port: int | None,
    log_db: str | None,
    *,
    approval_db: str = "~/.avakill/approvals.db",
    enforce: bool = False,
) -> None:
    """Launch daemon as a detached background process."""
    import subprocess
    import time

    cmd = [sys.executable, "-m", "avakill", "daemon", "start", "--foreground", "--policy", policy]
    if socket and sys.platform != "win32":
        cmd.extend(["--socket", socket])
    if tcp_port is not None:
        cmd.extend(["--tcp-port", str(tcp_port)])
    if log_db:
        cmd.extend(["--log-db", log_db])
    cmd.extend(["--approval-db", approval_db])
    if enforce:
        cmd.append("--enforce")

    popen_kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
    }
    if sys.platform == "win32":
        # DETACHED_PROCESS | CREATE_NO_WINDOW
        popen_kwargs["creationflags"] = 0x00000008 | 0x08000000
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **popen_kwargs)

    # Give child time to initialize (socket bind, policy load, etc.)
    time.sleep(1.0)

    exit_code = proc.poll()
    if exit_code is not None:
        # Child died during startup — show the error
        stderr_output = ""
        if proc.stderr:
            stderr_output = proc.stderr.read().decode(errors="replace").strip()
            proc.stderr.close()
        click.echo(f"Error: daemon exited immediately (code {exit_code}).", err=True)
        if stderr_output:
            click.echo(stderr_output, err=True)
        raise SystemExit(1)

    # Child is alive — close our end of the pipe and report success
    if proc.stderr:
        proc.stderr.close()
    click.echo(f"Daemon started (PID {proc.pid}).")
