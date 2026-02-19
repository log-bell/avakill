"""No-op sandbox backend for unsupported platforms."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import Any

from avakill.core.models import SandboxConfig

logger = logging.getLogger("avakill.launcher.sandbox")


class NoopSandboxBackend:
    """Fallback backend that applies no OS-level restrictions.

    Used on platforms where no sandbox mechanism is available.
    Logs a warning so users know enforcement is not active.
    """

    def available(self) -> bool:
        return True

    def prepare_preexec(self, config: SandboxConfig) -> Callable[[], None] | None:
        return None

    def prepare_process_args(self, config: SandboxConfig) -> dict[str, Any]:
        return {}

    def post_create(self, pid: int, config: SandboxConfig) -> None:
        logger.warning(
            "No sandbox backend available on %s. "
            "Child process %d is running without OS-level restrictions.",
            sys.platform,
            pid,
        )

    def describe(self, config: SandboxConfig) -> dict[str, Any]:
        return {
            "platform": "unsupported",
            "sandbox_applied": False,
            "reason": f"No sandbox backend for {sys.platform}",
        }
