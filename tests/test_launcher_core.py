"""Tests for ProcessLauncher core class."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.landlock import LandlockEnforcer
from avakill.launcher.backends.base import SandboxBackend
from avakill.launcher.backends.noop import NoopSandboxBackend
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
        assert env["AVAKILL_SOCKET"] == str(Path("/tmp/test.sock"))

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
        launcher = ProcessLauncher(policy=_allow_policy(), backend=NoopSandboxBackend())
        result = launcher.launch(["false"], dry_run=True)
        assert result.exit_code == 0
        assert result.pid == 0
        assert result.sandbox_applied is False

    def test_launch_dry_run_returns_sandbox_features(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["echo"], dry_run=True)
        assert isinstance(result.sandbox_features, dict)


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
        from avakill.launcher.backends.landlock_backend import LandlockBackend

        launcher = ProcessLauncher(policy=_deny_policy(), backend=LandlockBackend())
        result = launcher.launch(["true"])
        assert result.sandbox_applied is True

    def test_launch_with_noop_backend(self) -> None:
        launcher = ProcessLauncher(policy=_deny_policy(), backend=NoopSandboxBackend())
        result = launcher.launch(["true"])
        assert result.exit_code == 0
        assert result.sandbox_applied is True  # NoopSandboxBackend.available() is True

    def test_launch_sandbox_features_reported_in_result(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        result = launcher.launch(["true"], dry_run=True)
        features = result.sandbox_features
        assert isinstance(features, dict)


class TestProcessLauncherBackend:
    """Tests for SandboxBackend integration."""

    def test_uses_provided_backend(self) -> None:
        mock_backend = MagicMock(spec=SandboxBackend)
        mock_backend.prepare_preexec.return_value = None
        mock_backend.prepare_process_args.return_value = {}
        mock_backend.available.return_value = True
        launcher = ProcessLauncher(
            policy=_allow_policy(),
            backend=mock_backend,
        )
        assert launcher._backend is mock_backend

    def test_auto_detects_backend_when_none_provided(self) -> None:
        launcher = ProcessLauncher(policy=_allow_policy())
        assert isinstance(launcher._backend, SandboxBackend)

    def test_dry_run_includes_backend_description(self) -> None:
        mock_backend = MagicMock(spec=SandboxBackend)
        mock_backend.describe.return_value = {
            "platform": "test",
            "sandbox_applied": True,
        }
        launcher = ProcessLauncher(
            policy=_allow_policy(),
            backend=mock_backend,
        )
        result = launcher.launch(["echo", "test"], dry_run=True)
        mock_backend.describe.assert_called_once()
        assert result.sandbox_applied is True

    def test_launch_calls_post_create(self) -> None:
        mock_backend = MagicMock(spec=SandboxBackend)
        mock_backend.prepare_preexec.return_value = None
        mock_backend.prepare_process_args.return_value = {}
        mock_backend.wrap_command.side_effect = lambda cmd, cfg: cmd
        mock_backend.available.return_value = True
        mock_backend.describe.return_value = {"sandbox_applied": True}
        launcher = ProcessLauncher(
            policy=_allow_policy(),
            backend=mock_backend,
        )
        launcher.launch(["echo", "test"])
        mock_backend.post_create.assert_called_once()


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
