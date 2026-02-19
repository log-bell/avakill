"""Tests for ProcessLauncher core class."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import pytest

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.landlock import LandlockEnforcer
from avakill.launcher.core import LaunchResult, ProcessLauncher, _parse_ports


def _allow_policy() -> PolicyConfig:
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[PolicyRule(name="allow-all", tools=["*"], action="allow")],
    )


def _deny_policy() -> PolicyConfig:
    return PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[PolicyRule(name="deny-write", tools=["file_write"], action="deny")],
    )


class TestProcessLauncher:
    """Tests for ProcessLauncher.launch()."""

    def test_launch_simple_command_returns_exit_code(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["echo", "hello"])
        assert result.exit_code == 0
        assert result.pid > 0
        assert result.duration_seconds >= 0.0
        assert isinstance(result, LaunchResult)

    def test_launch_propagates_nonzero_exit_code(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["false"])
        assert result.exit_code != 0

    def test_launch_sets_avakill_env_vars(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        env = launcher._build_env()
        assert env["AVAKILL_POLICY"] == "active"

    def test_launch_sets_avakill_socket_env(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy(), socket_path=Path("/tmp/test.sock"))
        env = launcher._build_env()
        assert env["AVAKILL_SOCKET"] == "/tmp/test.sock"

    def test_launch_inherits_parent_env_by_default(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        env = launcher._build_env()
        # Should inherit PATH from parent
        assert "PATH" in env

    def test_launch_custom_env(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        env = launcher._build_env({"MY_VAR": "my_value"})
        assert env["MY_VAR"] == "my_value"
        assert env["AVAKILL_POLICY"] == "active"

    def test_launch_custom_cwd(self, tmp_path: Path) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["pwd"], cwd=tmp_path)
        assert result.exit_code == 0

    def test_launch_dry_run_does_not_execute(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["false"], dry_run=True)
        assert result.exit_code == 0
        assert result.pid == 0
        assert result.sandbox_applied is False

    def test_launch_dry_run_returns_sandbox_features(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["echo"], dry_run=True)
        assert isinstance(result.sandbox_features, dict)
        assert "filesystem" in result.sandbox_features


class TestProcessLauncherSignals:
    """Tests for signal forwarding."""

    @pytest.mark.skipif(sys.platform == "win32", reason="No SIGTERM on Windows")
    def test_sigterm_forwarded_to_child(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        # Verify signal forwarding installs and restores handlers
        launcher._install_signal_forwarding(os.getpid())
        assert signal.SIGTERM in launcher._original_handlers
        launcher._restore_signals()
        assert len(launcher._original_handlers) == 0

    @pytest.mark.skipif(sys.platform == "win32", reason="No SIGINT on Windows")
    def test_sigint_forwarded_to_child(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        launcher._install_signal_forwarding(os.getpid())
        assert signal.SIGINT in launcher._original_handlers
        launcher._restore_signals()

    def test_child_exit_restores_parent_signals(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["true"])
        assert result.exit_code == 0
        # After launch completes, original handlers should be restored
        assert len(launcher._original_handlers) == 0


class TestProcessLauncherSandbox:
    """Tests for sandbox integration."""

    @pytest.mark.skipif(not LandlockEnforcer.available(), reason="Landlock not available")
    def test_launch_with_landlock_restricts_child(self) -> None:
        launcher = ProcessLauncher(policy=_deny_policy())
        result = launcher.launch(["true"])
        assert result.sandbox_applied is True
        assert result.sandbox_features.get("filesystem") is True

    def test_launch_without_landlock_warns_and_continues(self) -> None:
        if LandlockEnforcer.available():
            pytest.skip("Landlock is available — this test is for non-Linux")
        launcher = ProcessLauncher(policy=_deny_policy())
        with pytest.warns(UserWarning, match="Landlock not available"):
            result = launcher.launch(["true"])
        assert result.exit_code == 0
        assert result.sandbox_applied is False

    def test_launch_sandbox_features_reported_in_result(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["true"], dry_run=True)
        features = result.sandbox_features
        assert isinstance(features, dict)
        expected_keys = {
            "filesystem",
            "file_refer",
            "file_truncate",
            "network_tcp",
            "device_ioctl",
            "ipc_scoping",
        }
        assert set(features.keys()) == expected_keys


class TestParsePortsHelper:
    """Tests for _parse_ports utility."""

    def test_parse_host_port(self) -> None:
        assert _parse_ports(["api.anthropic.com:443"]) == [443]

    def test_parse_bare_port(self) -> None:
        assert _parse_ports(["8080"]) == [8080]

    def test_parse_invalid_port_skipped(self) -> None:
        assert _parse_ports(["not-a-port"]) == []

    def test_parse_multiple_ports(self) -> None:
        assert _parse_ports(["api.example.com:443", "localhost:8080"]) == [443, 8080]
