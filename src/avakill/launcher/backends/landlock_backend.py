"""Landlock sandbox backend for Linux process launcher."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from avakill.core.models import SandboxConfig
from avakill.enforcement.landlock import LandlockEnforcer

logger = logging.getLogger("avakill.launcher.sandbox")


class LandlockBackend:
    """Landlock-based sandbox backend for Linux (kernel 5.13+).

    Applies Landlock filesystem and network restrictions to a child process
    via preexec_fn. Uses the existing LandlockEnforcer for ABI detection
    and syscall wrappers, but targets the child process (not self).
    """

    def available(self) -> bool:
        if sys.platform != "linux":
            return False
        return LandlockEnforcer.available()

    def prepare_preexec(self, config: SandboxConfig) -> Callable[[], None] | None:
        if not self.available():
            logger.warning("Landlock not available; child will run unsandboxed.")
            return None

        enforcer = LandlockEnforcer()
        abi = enforcer.abi_version()
        paths = config.allow_paths
        network = config.allow_network

        read_paths = [str(Path(p).expanduser().resolve()) for p in paths.read]
        write_paths = [str(Path(p).expanduser().resolve()) for p in paths.write]
        exec_paths = [str(Path(p).expanduser().resolve()) for p in paths.execute]

        connect_ports: list[int] = []
        if abi >= 4:
            for entry in network.connect:
                port = self._parse_port(entry)
                if port is not None:
                    connect_ports.append(port)

        def _preexec() -> None:
            """Apply Landlock restrictions in child process.

            SAFETY: Only calls async-signal-safe functions.
            """
            enforcer.apply_to_child(
                read_paths=read_paths,
                write_paths=write_paths,
                exec_paths=exec_paths,
                connect_ports=connect_ports,
                abi_version=abi,
            )

        return _preexec

    def prepare_process_args(self, config: SandboxConfig) -> dict[str, Any]:
        return {}

    def post_create(self, pid: int, config: SandboxConfig) -> None:
        pass

    def describe(self, config: SandboxConfig) -> dict[str, Any]:
        if not self.available():
            return {
                "platform": "linux",
                "sandbox_applied": False,
                "reason": "Landlock not available on this kernel",
            }

        enforcer = LandlockEnforcer()
        abi = enforcer.abi_version()
        features = enforcer.supported_features(abi)
        paths = config.allow_paths

        return {
            "platform": "linux",
            "sandbox_applied": True,
            "mechanism": "landlock",
            "abi_version": abi,
            "features": features,
            "allowed_read_paths": paths.read,
            "allowed_write_paths": paths.write,
            "allowed_exec_paths": paths.execute,
            "allowed_network_connect": config.allow_network.connect if abi >= 4 else [],
        }

    @staticmethod
    def _parse_port(entry: str) -> int | None:
        """Extract port from 'host:port' or plain port string."""
        if ":" in entry:
            try:
                return int(entry.rsplit(":", 1)[1])
            except ValueError:
                return None
        try:
            return int(entry)
        except ValueError:
            return None
