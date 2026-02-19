"""Core process launcher with OS-level sandbox support.

Launches a child process inside an OS-level sandbox (Landlock on Linux).
The sandbox is applied in the child's preexec_fn — after fork, before the
target command replaces the process — so the child inherits the restrictions
and cannot escape them.
"""

from __future__ import annotations

import logging
import os
import resource
import signal
import subprocess
import time
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from avakill.core.models import PolicyConfig

logger = logging.getLogger(__name__)


class LaunchResult(BaseModel):
    """Result of a launched process."""

    exit_code: int
    pid: int
    sandbox_applied: bool
    sandbox_features: dict[str, bool] = Field(default_factory=dict)
    duration_seconds: float


class ProcessLauncher:
    """Launch a process inside an OS-level sandbox.

    The launcher:
    1. Parses the policy to derive sandbox restrictions
    2. Forks a child process
    3. Applies OS-level restrictions in the child (before target runs)
    4. Forwards signals from parent to child
    5. Waits for child exit and propagates exit code
    """

    def __init__(
        self,
        policy: PolicyConfig,
        socket_path: Path | None = None,
    ) -> None:
        self._policy = policy
        self._socket_path = socket_path
        self._original_handlers: dict[int, Any] = {}

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
        from avakill.enforcement.landlock import LandlockEnforcer

        enforcer = LandlockEnforcer()
        sandbox_available = enforcer.available()
        abi = enforcer.abi_version()
        features = enforcer.supported_features(abi)

        if dry_run:
            return LaunchResult(
                exit_code=0,
                pid=0,
                sandbox_applied=False,
                sandbox_features=features,
                duration_seconds=0.0,
            )

        if not sandbox_available:
            warnings.warn(
                "Landlock not available on this platform. "
                "Process will launch without OS-level sandbox.",
                stacklevel=2,
            )

        child_env = self._build_env(env)
        preexec_fn = self._build_preexec_fn() if sandbox_available else None

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
                )
                os.close(slave_fd)
                self._install_signal_forwarding(process.pid)
                exit_code = relay.relay(master_fd, process)
            finally:
                os.close(master_fd)
                self._restore_signals()
        else:
            process = subprocess.Popen(
                command,
                env=child_env,
                cwd=str(cwd) if cwd else None,
                preexec_fn=preexec_fn,
            )
            self._install_signal_forwarding(process.pid)
            exit_code = self._wait_for_child(process)
            self._restore_signals()

        duration = time.monotonic() - start

        return LaunchResult(
            exit_code=exit_code,
            pid=process.pid,
            sandbox_applied=sandbox_available,
            sandbox_features=features,
            duration_seconds=duration,
        )

    def _build_preexec_fn(self) -> Callable[[], None]:
        """Build the preexec function that runs in child after fork.

        Only calls async-signal-safe functions:
        - ctypes syscalls (Landlock)
        - resource.setrlimit
        - os.setsid (for process group)
        """
        policy = self._policy
        sandbox = policy.sandbox

        def _preexec() -> None:
            import ctypes
            import ctypes.util

            from avakill.enforcement.landlock import (
                ALL_ACCESS_FS,
                LANDLOCK_ACCESS_NET_BIND_TCP,
                LANDLOCK_ACCESS_NET_CONNECT_TCP,
                LANDLOCK_ADD_RULE,
                LANDLOCK_CREATE_RULESET,
                LANDLOCK_RESTRICT_SELF,
                LANDLOCK_RULE_PATH_BENEATH,
                LandlockPathBeneathAttr,
                LandlockRulesetAttr,
            )

            os.setsid()

            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

            # prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            PR_SET_NO_NEW_PRIVS = 38  # noqa: N806
            libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

            # Determine handled flags from policy deny rules
            from avakill.enforcement.landlock import LandlockEnforcer

            enforcer = LandlockEnforcer()
            abi = enforcer.abi_version()
            ruleset_info = enforcer.generate_ruleset(policy)
            handled_fs = ruleset_info["handled_access_fs"]

            # Determine network flags
            handled_net = 0
            if abi >= 4 and sandbox and sandbox.allow_network.connect:
                handled_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP
            if abi >= 4 and sandbox and sandbox.allow_network.bind:
                handled_net |= LANDLOCK_ACCESS_NET_BIND_TCP

            if handled_fs == 0 and handled_net == 0:
                return  # Nothing to restrict

            # Create ruleset
            attr = LandlockRulesetAttr(
                handled_access_fs=handled_fs,
                handled_access_net=handled_net,
            )
            ruleset_fd = libc.syscall(
                LANDLOCK_CREATE_RULESET,
                ctypes.byref(attr),
                ctypes.sizeof(attr),
                0,
            )
            if ruleset_fd < 0:
                return  # Silently degrade if syscall fails

            try:
                # Add default root rule for non-restricted access
                allowed_access = ALL_ACCESS_FS & ~handled_fs
                if allowed_access:
                    root_fd = os.open("/", os.O_PATH | os.O_DIRECTORY)  # type: ignore[attr-defined]
                    try:
                        path_attr = LandlockPathBeneathAttr(
                            allowed_access=allowed_access,
                            parent_fd=root_fd,
                        )
                        libc.syscall(
                            LANDLOCK_ADD_RULE,
                            ruleset_fd,
                            LANDLOCK_RULE_PATH_BENEATH,
                            ctypes.byref(path_attr),
                            0,
                        )
                    finally:
                        os.close(root_fd)

                # Add per-path rules from sandbox config
                if sandbox and sandbox.allow_paths:
                    enforcer.apply_path_rules(
                        ruleset_fd,
                        {
                            "read": sandbox.allow_paths.read,
                            "write": sandbox.allow_paths.write,
                            "execute": sandbox.allow_paths.execute,
                        },
                        handled_fs,
                    )

                # Add network rules from sandbox config
                if sandbox and handled_net:
                    connect_ports = _parse_ports(sandbox.allow_network.connect)
                    bind_ports = _parse_ports(sandbox.allow_network.bind)
                    enforcer.apply_network_rules(ruleset_fd, connect_ports, bind_ports)

                # Restrict self
                libc.syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
            finally:
                os.close(ruleset_fd)

            # Apply resource limits
            if sandbox and sandbox.resource_limits:
                limits = sandbox.resource_limits
                if limits.max_memory_mb is not None:
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

        return _preexec

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
        for sig in (signal.SIGTERM, signal.SIGINT):
            old = signal.signal(sig, lambda s, f, pid=child_pid: os.kill(pid, s))
            self._original_handlers[sig] = old

    def _restore_signals(self) -> None:
        """Restore original signal handlers."""
        for sig, handler in self._original_handlers.items():
            signal.signal(sig, handler)
        self._original_handlers.clear()

    def _wait_for_child(self, process: subprocess.Popen) -> int:
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
