"""SandboxBackend protocol - the contract for platform-specific sandboxing."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from avakill.core.models import PolicyConfig, SandboxConfig


@runtime_checkable
class SandboxBackend(Protocol):
    """Protocol for OS-level sandbox backends.

    Each platform provides a backend that applies restrictions to a child
    process. Unix backends use prepare_preexec() to return a function that
    runs in the child after fork (before exec). Windows uses post_create()
    to configure a suspended process before resuming it.
    """

    def available(self) -> bool:
        """Return True if this backend can operate on the current system."""
        ...

    def prepare_preexec(self, config: SandboxConfig) -> Callable[[], None] | None:
        """Return a preexec_fn for subprocess.Popen (Unix only).

        The returned function runs in the child process after fork(),
        before exec(). It MUST only call async-signal-safe functions:
        raw syscalls via ctypes, resource.setrlimit, os.setsid.

        Returns None on Windows or if no preexec setup is needed.
        """
        ...

    def prepare_process_args(self, config: SandboxConfig) -> dict[str, Any]:
        """Return extra kwargs for subprocess.Popen.

        On Windows, returns creationflags for CREATE_SUSPENDED.
        On Unix, typically returns an empty dict.
        """
        ...

    def post_create(self, pid: int, config: SandboxConfig) -> None:
        """Post-creation setup for a child process.

        On Windows: assign AppContainer, Job Object, remove privileges,
        then resume the thread. On Unix: typically a no-op.
        """
        ...

    def wrap_command(self, command: list[str], config: SandboxConfig) -> list[str]:
        """Optionally wrap the command for external sandbox enforcement.

        Backends that apply sandboxing by wrapping the command (e.g.,
        sandbox-exec -f profile) override this method.  The default
        returns the command unchanged.
        """
        ...

    def cleanup(self) -> None:
        """Clean up any resources created during sandboxing.

        Called after the child process exits.  Backends that create
        temporary files (e.g., .sb profiles) should remove them here.
        """
        ...

    def describe(self, config: SandboxConfig) -> dict[str, Any]:
        """Return a dry-run report of what restrictions would be applied."""
        ...


def get_sandbox_backend(policy: PolicyConfig | None = None) -> SandboxBackend:
    """Auto-detect and return the appropriate sandbox backend.

    Returns:
        LandlockBackend on Linux, MacOSSandboxBackend on macOS,
        WindowsSandboxBackend on Windows, NoopSandboxBackend otherwise.
    """
    if sys.platform == "linux":
        from avakill.launcher.backends.landlock_backend import LandlockBackend

        return LandlockBackend()

    if sys.platform == "darwin":
        from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend

        return MacOSSandboxBackend(policy)

    if sys.platform == "win32":
        from avakill.launcher.backends.windows_backend import WindowsSandboxBackend

        return WindowsSandboxBackend()

    from avakill.launcher.backends.noop import NoopSandboxBackend

    return NoopSandboxBackend()
