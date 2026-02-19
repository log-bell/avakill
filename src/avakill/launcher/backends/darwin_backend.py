"""macOS sandbox backend using sandbox_init_with_parameters().

Calls Apple's private sandbox_init_with_parameters() API via ctypes
to apply a Seatbelt (SBPL) profile to the child process in preexec_fn.
This is the same mechanism used by OpenAI's Codex CLI and Google's Bazel.

WARNING: sandbox_init_with_parameters() is a private API. Apple has
deprecated sandbox-exec but has not removed it or its underlying API
as of macOS 15 Sequoia (February 2026). Monitor Apple's direction.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable
from typing import Any

from avakill.core.models import SandboxConfig
from avakill.launcher.backends.darwin_sbpl import generate_sbpl_profile

logger = logging.getLogger("avakill.launcher.sandbox")


class DarwinSandboxBackend:
    """macOS sandbox backend using sandbox_init_with_parameters().

    Applies an allow-based SBPL profile to the child process before exec.
    Falls back to NoopSandboxBackend behavior on non-macOS platforms.
    """

    def available(self) -> bool:
        return sys.platform == "darwin"

    def prepare_preexec(self, config: SandboxConfig) -> Callable[[], None] | None:
        if not self.available():
            return None

        sbpl_profile = generate_sbpl_profile(config)
        profile_bytes = sbpl_profile.encode("utf-8")

        def _preexec() -> None:
            """Apply sandbox_init_with_parameters in child process.

            SAFETY: Only calls async-signal-safe functions.
            ctypes.CDLL and sandbox_init_with_parameters are safe here
            because the child is single-threaded after fork.
            """
            import ctypes

            try:
                libsystem = ctypes.CDLL("libSystem.dylib")
            except OSError:
                os._exit(126)

            err_ptr = ctypes.c_char_p()

            # flags=0 means interpret the first arg as inline SBPL
            rc = libsystem.sandbox_init_with_parameters(
                profile_bytes,
                0,
                ctypes.byref(err_ptr),
                None,
            )

            if rc != 0:
                if err_ptr.value:
                    libsystem.sandbox_free_error(err_ptr)
                os._exit(126)

        return _preexec

    def prepare_process_args(self, config: SandboxConfig) -> dict[str, Any]:
        return {}

    def post_create(self, pid: int, config: SandboxConfig) -> None:
        pass

    def describe(self, config: SandboxConfig) -> dict[str, Any]:
        if not self.available():
            return {
                "platform": "darwin",
                "sandbox_applied": False,
                "reason": "Not running on macOS",
            }

        sbpl_profile = generate_sbpl_profile(config)
        paths = config.allow_paths

        return {
            "platform": "darwin",
            "sandbox_applied": True,
            "mechanism": "sandbox_init_with_parameters",
            "sbpl_profile": sbpl_profile,
            "allowed_read_paths": paths.read,
            "allowed_write_paths": paths.write,
            "allowed_exec_paths": paths.execute,
            "allowed_network_connect": config.allow_network.connect,
        }
