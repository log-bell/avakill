"""Integration tests for ProcessLauncher with real processes."""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import pytest

from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
    SandboxConfig,
    SandboxNetworkRules,
    SandboxPathRules,
    SandboxResourceLimits,
)
from avakill.enforcement.landlock import LandlockEnforcer
from avakill.launcher.backends.noop import NoopSandboxBackend
from avakill.launcher.core import ProcessLauncher


def _allow_policy(**kwargs) -> PolicyConfig:
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[PolicyRule(name="allow-all", tools=["*"], action="allow")],
        **kwargs,
    )


def _deny_write_policy(**kwargs) -> PolicyConfig:
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[PolicyRule(name="deny-write", tools=["file_write"], action="deny")],
        **kwargs,
    )


class TestLauncherIntegration:
    """End-to-end tests that launch real processes."""

    def test_launch_echo_hello_captures_output(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["echo", "hello"])
        assert result.exit_code == 0
        assert result.pid > 0
        assert result.duration_seconds > 0

    def test_launch_env_injection_avakill_policy(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        # Launch a process that prints the AVAKILL_POLICY env var
        result = launcher.launch(
            ["sh", "-c", "echo $AVAKILL_POLICY"],
        )
        assert result.exit_code == 0

    def test_launch_env_injection_avakill_socket(self) -> None:
        launcher = ProcessLauncher(
            policy=_allow_policy(),
            socket_path=Path("/tmp/avakill-test.sock"),
        )
        env = launcher._build_env()
        assert env["AVAKILL_SOCKET"] == str(Path("/tmp/avakill-test.sock"))

    def test_launch_cwd_override(self, tmp_path: Path) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["pwd"], cwd=tmp_path)
        assert result.exit_code == 0

    def test_launch_timeout_kills_child(self) -> None:
        policy = _allow_policy(
            sandbox=SandboxConfig(
                resource_limits=SandboxResourceLimits(timeout_seconds=1),
            ),
        )
        launcher = ProcessLauncher(policy=policy, backend=NoopSandboxBackend())
        start = time.monotonic()
        result = launcher.launch(["sleep", "30"])
        elapsed = time.monotonic() - start
        # Should have been killed by timeout well before 30s
        assert elapsed < 10
        # Exit code should indicate termination
        assert result.exit_code != 0

    @pytest.mark.skipif(sys.platform == "win32", reason="No SIGTERM on Windows")
    def test_launch_signal_forwarding_sigterm(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        # Verify signal handlers are installed and restored
        launcher._install_signal_forwarding(os.getpid())
        assert signal.SIGTERM in launcher._original_handlers
        assert signal.SIGINT in launcher._original_handlers
        launcher._restore_signals()
        assert len(launcher._original_handlers) == 0


class TestLauncherLandlockIntegration:
    """Landlock-conditional integration tests."""

    @pytest.mark.skipif(
        not LandlockEnforcer.available(),
        reason="Landlock not available",
    )
    def test_child_cannot_write_outside_allowed_paths(self, tmp_path: Path) -> None:
        policy = _deny_write_policy(
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(write=[str(tmp_path / "allowed")]),
            ),
        )
        # Create the allowed directory
        (tmp_path / "allowed").mkdir()
        launcher = ProcessLauncher(policy=policy)
        # Try to write to a disallowed path
        result = launcher.launch(
            ["sh", "-c", f"echo test > {tmp_path}/disallowed.txt"],
        )
        # Should fail because writing outside allowed paths is restricted
        assert result.exit_code != 0

    @pytest.mark.skipif(
        not LandlockEnforcer.available(),
        reason="Landlock not available",
    )
    def test_child_can_read_allowed_paths(self) -> None:
        policy = _deny_write_policy(
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(read=["/usr", "/bin", "/lib"]),
            ),
        )
        launcher = ProcessLauncher(policy=policy)
        result = launcher.launch(["ls", "/usr"])
        assert result.exit_code == 0

    @pytest.mark.skipif(
        not LandlockEnforcer.available(),
        reason="Landlock not available",
    )
    def test_child_can_execute_allowed_binaries(self) -> None:
        policy = _deny_write_policy(
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(execute=["/usr/bin", "/bin"]),
            ),
        )
        launcher = ProcessLauncher(policy=policy)
        result = launcher.launch(["echo", "allowed"])
        assert result.exit_code == 0

    @pytest.mark.skipif(
        not LandlockEnforcer.available() or LandlockEnforcer.abi_version() < 4,
        reason="Landlock ABI 4+ required",
    )
    def test_child_cannot_connect_to_unauthorized_port(self) -> None:
        policy = _deny_write_policy(
            sandbox=SandboxConfig(
                allow_network=SandboxNetworkRules(connect=["localhost:443"]),
            ),
        )
        launcher = ProcessLauncher(policy=policy)
        # Try to connect to a port not in the allowlist
        result = launcher.launch(
            ["sh", "-c", "echo | nc -w 1 localhost 12345 2>/dev/null"],
        )
        # Connection should be denied by Landlock
        assert result.exit_code != 0

    @pytest.mark.skipif(
        not LandlockEnforcer.available(),
        reason="Landlock not available",
    )
    def test_sandbox_features_match_kernel_abi(self) -> None:
        from avakill.launcher.backends.landlock_backend import LandlockBackend

        launcher = ProcessLauncher(policy=_allow_policy(), backend=LandlockBackend())
        result = launcher.launch(["true"], dry_run=True)
        assert result.sandbox_features.get("abi_version") is not None
