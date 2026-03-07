"""macOS sandbox-exec backend for the process launcher.

Generates an SBPL profile from the policy's sandbox config, then wraps
the child command with ``sandbox-exec -f <profile> -D KEY=VALUE ...``.

Always uses deny-default profiles with broad reads + scoped writes.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from avakill.core.models import PolicyConfig, SandboxConfig

logger = logging.getLogger("avakill.launcher.sandbox")

SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec"


class MacOSSandboxBackend:
    """macOS sandbox backend using sandbox-exec command wrapping.

    Generates a deny-default SBPL profile via
    ``darwin_sbpl.generate_sbpl_profile()`` and wraps the command with
    ``sandbox-exec -f <profile> -D KEY=VALUE ...``.
    """

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self._policy = policy or PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[],
        )
        self._profile_path: Path | None = None
        self._profile_content: str | None = None
        self._keep_profile: bool = False

    def available(self) -> bool:
        """Check if sandbox-exec is available on this system."""
        return sys.platform == "darwin" and os.path.isfile(SANDBOX_EXEC_PATH)

    def prepare_preexec(self, config: SandboxConfig) -> None:
        return None

    def prepare_process_args(self, config: SandboxConfig) -> dict[str, Any]:
        return {}

    def post_create(self, pid: int, config: SandboxConfig) -> None:
        pass

    def wrap_command(self, command: list[str], config: SandboxConfig) -> list[str]:
        """Wrap the command with sandbox-exec -f <profile> -D KEY=VALUE ...

        Generates the SBPL profile, writes it to a temp file, and
        returns the wrapped command with -D parameters.
        """
        if not self.available():
            logger.warning("sandbox-exec not available; running without sandbox.")
            return command

        profile = self._generate_profile()
        profile_path = self._write_temp_profile(profile)
        params = self._generate_params()

        cmd = [SANDBOX_EXEC_PATH, "-f", str(profile_path)]
        for key, value in params.items():
            cmd.extend(["-D", f"{key}={value}"])
        cmd.extend(command)
        return cmd

    def describe(self, config: SandboxConfig) -> dict[str, Any]:
        """Return a dry-run report including the generated SBPL profile."""
        if not self.available():
            return {
                "platform": "darwin",
                "sandbox_applied": False,
                "backend": "sandbox-exec",
                "reason": "sandbox-exec not found at " + SANDBOX_EXEC_PATH,
            }

        try:
            profile = self._generate_profile()
        except Exception as exc:
            return {
                "platform": "darwin",
                "sandbox_applied": False,
                "backend": "sandbox-exec",
                "reason": f"Profile generation failed: {exc}",
            }

        sandbox_cfg = self._policy.sandbox or SandboxConfig()

        return {
            "platform": "darwin",
            "sandbox_applied": True,
            "backend": "sandbox-exec",
            "mechanism": "sandbox-exec",
            "sbpl_profile": profile,
            "filesystem": True,
            "allowed_write_paths": list(sandbox_cfg.allow_paths.write),
            "denied_read_paths": list(sandbox_cfg.deny_paths.read),
            "allowed_network": list(sandbox_cfg.allow_network.connect),
        }

    def get_profile_content(self) -> str:
        """Return the generated SBPL profile content."""
        if self._profile_content is None:
            self._profile_content = self._generate_profile()
        return self._profile_content

    def set_keep_profile(self, keep: bool) -> None:
        """If True, the temp profile file is not cleaned up on exit."""
        self._keep_profile = keep

    @property
    def profile_path(self) -> Path | None:
        """Path to the generated temp .sb profile, if any."""
        return self._profile_path

    def cleanup(self) -> None:
        """Remove the temp profile file unless keep_profile is set."""
        if self._profile_path and not self._keep_profile:
            with contextlib.suppress(OSError):
                self._profile_path.unlink(missing_ok=True)
            self._profile_path = None

    def _generate_profile(self) -> str:
        """Generate deny-default SBPL profile."""
        if self._profile_content is not None:
            return self._profile_content

        from avakill.launcher.backends.darwin_sbpl import generate_sbpl_profile

        sandbox_cfg = self._policy.sandbox or SandboxConfig()
        self._profile_content = generate_sbpl_profile(sandbox_cfg)
        return self._profile_content

    def _generate_params(self) -> dict[str, str]:
        """Generate -D parameters for sandbox-exec."""
        from avakill.launcher.backends.darwin_sbpl import generate_sbpl_params

        sandbox_cfg = self._policy.sandbox or SandboxConfig()
        return generate_sbpl_params(sandbox_cfg)

    def _write_temp_profile(self, profile: str) -> Path:
        """Write profile to a temp file and return the path."""
        if self._profile_path is not None:
            return self._profile_path

        fd, path_str = tempfile.mkstemp(suffix=".sb", prefix="avakill-")
        try:
            os.write(fd, profile.encode("utf-8"))
        finally:
            os.close(fd)

        self._profile_path = Path(path_str)
        return self._profile_path
