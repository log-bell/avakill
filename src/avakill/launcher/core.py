"""Core process launcher with cross-platform sandbox support.

Launches a child process inside an OS-level sandbox. The sandbox backend
is auto-detected per platform: Landlock on Linux, sandbox_init on macOS,
AppContainer + Job Objects on Windows, no-op elsewhere.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from avakill.core.models import PolicyConfig, SandboxConfig
from avakill.launcher.backends.base import SandboxBackend, get_sandbox_backend

logger = logging.getLogger(__name__)


class LaunchResult(BaseModel):
    """Result of a launched process."""

    exit_code: int
    pid: int
    sandbox_applied: bool
    sandbox_features: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float


class ProcessLauncher:
    """Launch a process inside an OS-level sandbox.

    The launcher:
    1. Auto-detects the platform sandbox backend (or uses a provided one)
    2. Forks a child process with backend-provided preexec_fn and process args
    3. Calls backend.post_create() for post-fork setup (Windows: resume thread)
    4. Forwards signals from parent to child
    5. Waits for child exit and propagates exit code
    """

    def __init__(
        self,
        policy: PolicyConfig,
        socket_path: Path | None = None,
        backend: SandboxBackend | None = None,
    ) -> None:
        self._policy = policy
        self._socket_path = socket_path
        self._sandbox_config = policy.sandbox or SandboxConfig()
        self._original_handlers: dict[int, Any] = {}

        if backend is not None:
            self._backend = backend
        elif policy.sandbox is not None:
            # Sandbox explicitly configured — use platform backend
            self._backend = get_sandbox_backend()
        else:
            # No sandbox section — no OS-level sandboxing
            from avakill.launcher.backends.noop import NoopSandboxBackend

            self._backend = NoopSandboxBackend()

    def launch(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        pty: bool = False,
        dry_run: bool = False,
    ) -> LaunchResult:
        """Launch command inside sandbox. Blocks until child exits.

        Args:
            command: The command and arguments to run.
            env: Additional environment variables for the child.
            cwd: Working directory for the child.
            pty: If True, allocate a PTY for interactive agents.
            dry_run: If True, show sandbox info without launching.

        Returns:
            LaunchResult with exit code, sandbox info, and timing.
        """
        if dry_run:
            report = self._backend.describe(self._sandbox_config)
            return LaunchResult(
                exit_code=0,
                pid=0,
                sandbox_applied=report.get("sandbox_applied", False),
                sandbox_features=report,
                duration_seconds=0.0,
            )

        preexec_fn = self._build_preexec_fn()
        extra_args = self._backend.prepare_process_args(self._sandbox_config)
        child_env = self._build_env(env)

        start = time.monotonic()

        if pty:
            from avakill.launcher.pty_relay import PTYRelay

            relay = PTYRelay()
            master_fd, slave_fd = relay.allocate()
            try:
                process = subprocess.Popen(
                    command,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    env=child_env,
                    cwd=str(cwd) if cwd else None,
                    preexec_fn=preexec_fn,
                    close_fds=True,
                    **extra_args,
                )
                os.close(slave_fd)
                self._backend.post_create(process.pid, self._sandbox_config)
                self._install_signal_forwarding(process.pid)
                exit_code = relay.relay(master_fd, process)
            finally:
                os.close(master_fd)
                self._restore_signals()
        else:
            popen_kwargs: dict[str, Any] = {
                "env": child_env,
                "cwd": str(cwd) if cwd else None,
                "preexec_fn": preexec_fn,
            }
            if sys.platform != "win32" and sys.version_info >= (3, 11):
                popen_kwargs["process_group"] = 0
            popen_kwargs.update(extra_args)

            process = subprocess.Popen(command, **popen_kwargs)
            self._backend.post_create(process.pid, self._sandbox_config)
            self._install_signal_forwarding(process.pid)
            exit_code = self._wait_for_child(process)
            self._restore_signals()

        duration = time.monotonic() - start

        return LaunchResult(
            exit_code=exit_code,
            pid=process.pid,
            sandbox_applied=self._backend.available(),
            sandbox_features=self._backend.describe(self._sandbox_config),
            duration_seconds=duration,
        )

    def _build_preexec_fn(self) -> Callable[[], None] | None:
        """Combine sandbox preexec + resource limits."""
        sandbox_fn = self._backend.prepare_preexec(self._sandbox_config)
        rlimit_fn = self._build_rlimit_fn()

        if sandbox_fn is None and rlimit_fn is None:
            return None

        def _combined() -> None:
            if sandbox_fn:
                sandbox_fn()
            if rlimit_fn:
                rlimit_fn()

        return _combined

    def _build_rlimit_fn(self) -> Callable[[], None] | None:
        """Build a function to apply resource limits via setrlimit."""
        if sys.platform == "win32":
            return None  # Windows uses Job Objects instead

        limits = self._sandbox_config.resource_limits
        has_limits = (
            limits.max_memory_mb is not None
            or limits.max_open_files is not None
            or limits.max_processes is not None
        )
        if not has_limits:
            return None

        def _apply_rlimits() -> None:
            import resource

            if limits.max_memory_mb is not None and sys.platform != "darwin":
                # macOS does not enforce RLIMIT_AS or RLIMIT_DATA via setrlimit;
                # memory containment on macOS relies on the sandbox profile instead.
                mem_bytes = limits.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            if limits.max_open_files is not None:
                resource.setrlimit(
                    resource.RLIMIT_NOFILE,
                    (limits.max_open_files, limits.max_open_files),
                )
            if limits.max_processes is not None:
                resource.setrlimit(
                    resource.RLIMIT_NPROC,
                    (limits.max_processes, limits.max_processes),
                )

        return _apply_rlimits

    def _build_env(self, base_env: dict[str, str] | None = None) -> dict[str, str]:
        """Build child environment with AVAKILL_POLICY and AVAKILL_SOCKET."""
        sandbox = self._policy.sandbox
        child_env = os.environ.copy() if sandbox is None or sandbox.inherit_env else {}

        # Inject AvaKill variables
        child_env["AVAKILL_POLICY"] = "active"
        if self._socket_path:
            child_env["AVAKILL_SOCKET"] = str(self._socket_path)

        # Override with user-provided env
        if base_env:
            child_env.update(base_env)

        return child_env

    def _install_signal_forwarding(self, child_pid: int) -> None:
        """Install parent signal handlers that forward to child."""

        def _forward(signum: int, frame: Any, pid: int = child_pid) -> None:
            os.kill(pid, signum)

        for sig in (signal.SIGTERM, signal.SIGINT):
            old = signal.signal(sig, _forward)
            self._original_handlers[sig] = old

    def _restore_signals(self) -> None:
        """Restore original signal handlers."""
        for sig, handler in self._original_handlers.items():
            signal.signal(sig, handler)
        self._original_handlers.clear()

    def _wait_for_child(self, process: subprocess.Popen) -> int:  # type: ignore[type-arg]
        """Wait for child, handle timeout, return exit code."""
        timeout = None
        if self._policy.sandbox and self._policy.sandbox.resource_limits.timeout_seconds:
            timeout = self._policy.sandbox.resource_limits.timeout_seconds

        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        return process.returncode if process.returncode is not None else 128


def _parse_ports(entries: list[str]) -> list[int]:
    """Extract port numbers from host:port strings."""
    ports = []
    for entry in entries:
        port_str = entry.rsplit(":", 1)[1] if ":" in entry else entry
        try:
            ports.append(int(port_str))
        except ValueError:
            continue
    return ports
