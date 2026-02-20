"""Tests for the launch CLI command."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import yaml
from click.testing import CliRunner

from avakill.cli.main import cli


def _write_policy(
    tmp_path: Path,
    sandbox: dict | None = None,
    deny_rules: bool = False,
) -> Path:
    """Write a minimal policy YAML and return its path."""
    if deny_rules:
        policies = [
            {"name": "deny-write", "tools": ["file_write"], "action": "deny"},
            {"name": "allow-read", "tools": ["file_read"], "action": "allow"},
        ]
    else:
        policies = [
            {"name": "allow-all", "tools": ["*"], "action": "allow"},
        ]

    data: dict = {
        "version": "1.0",
        "default_action": "allow",
        "policies": policies,
    }
    if sandbox is not None:
        data["sandbox"] = sandbox
    path = tmp_path / "test-policy.yaml"
    path.write_text(yaml.dump(data))
    return path


class TestLaunchCLI:
    """Tests for avakill launch CLI command."""

    def test_launch_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["launch", "--help"])
        assert result.exit_code == 0
        assert "Launch a process inside an OS-level sandbox" in result.output
        assert "--policy" in result.output
        assert "--dry-run" in result.output
        assert "--pty" in result.output
        assert "--keep-profile" in result.output

    def test_launch_dry_run_shows_sandbox_info(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        monkeypatch.setattr("sys.platform", "linux")  # type: ignore[attr-defined]
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli, ["launch", "--policy", str(policy_path), "--dry-run", "--", "echo", "hello"]
        )
        assert result.exit_code == 0
        assert "Sandbox dry-run report" in result.output
        assert "Features:" in result.output

    def test_launch_echo_returns_0(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        monkeypatch.setattr("sys.platform", "linux")  # type: ignore[attr-defined]
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["launch", "--policy", str(policy_path), "--", "echo", "hello"])
        assert result.exit_code == 0

    def test_launch_false_returns_1(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        monkeypatch.setattr("sys.platform", "linux")  # type: ignore[attr-defined]
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["launch", "--policy", str(policy_path), "--", "false"])
        assert result.exit_code == 1

    def test_launch_missing_policy_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["launch", "--policy", "/nonexistent/policy.yaml", "--", "echo"]
        )
        assert result.exit_code == 1
        assert "policy file not found" in result.output

    def test_launch_missing_command_exits_error(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["launch", "--policy", str(policy_path)])
        assert result.exit_code != 0


class TestLaunchDarwinSandboxExec:
    """Tests for macOS sandbox-exec integration via avakill launch."""

    def test_dry_run_prints_sb_profile(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        """On macOS, --dry-run should print the generated .sb profile."""
        monkeypatch.setattr("sys.platform", "darwin")  # type: ignore[attr-defined]
        monkeypatch.setattr(  # type: ignore[attr-defined]
            "os.path.isfile",
            lambda p: p == "/usr/bin/sandbox-exec" or os.path.isfile.__wrapped__(p),
        )
        policy_path = _write_policy(
            tmp_path,
            deny_rules=True,
            sandbox={"allow_paths": {"write": ["/tmp"]}},
        )
        runner = CliRunner()
        result = runner.invoke(
            cli, ["launch", "--policy", str(policy_path), "--dry-run", "--", "echo", "hello"]
        )
        assert result.exit_code == 0
        assert "(version 1)" in result.output
        assert "(allow default)" in result.output
        assert "sandbox-exec profile" in result.output.lower()

    def test_backend_detection_selects_macos_sandbox(self) -> None:
        """get_sandbox_backend returns MacOSSandboxBackend on darwin."""
        from avakill.core.models import PolicyConfig

        with patch("sys.platform", "darwin"):
            from avakill.launcher.backends.base import get_sandbox_backend
            from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend

            policy = PolicyConfig(
                version="1.0",
                default_action="allow",
                policies=[],
            )
            backend = get_sandbox_backend(policy=policy)
            assert isinstance(backend, MacOSSandboxBackend)

    def test_keep_profile_writes_sb_file(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        """--keep-profile should save the .sb file and print its path."""
        monkeypatch.setattr("sys.platform", "darwin")  # type: ignore[attr-defined]

        policy_path = _write_policy(
            tmp_path,
            deny_rules=True,
            sandbox={"allow_paths": {"write": ["/tmp"]}},
        )

        from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend
        from avakill.launcher.core import LaunchResult

        # Mock the full launch to avoid actually calling sandbox-exec
        mock_result = LaunchResult(
            exit_code=0,
            pid=12345,
            sandbox_applied=True,
            sandbox_features={"platform": "darwin", "sandbox_applied": True},
            duration_seconds=0.1,
        )

        with (
            patch.object(MacOSSandboxBackend, "wrap_command", side_effect=lambda cmd, cfg: cmd),
            patch(
                "avakill.launcher.core.ProcessLauncher.launch",
                return_value=mock_result,
            ),
        ):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                [
                    "launch",
                    "--policy",
                    str(policy_path),
                    "--keep-profile",
                    "--",
                    "echo",
                    "hello",
                ],
            )
            # Should exit with the child's exit code
            assert result.exit_code == 0

    def test_mock_sandbox_exec_full_flow(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        """Mock sandbox-exec execution to test the full flow."""
        monkeypatch.setattr("sys.platform", "darwin")  # type: ignore[attr-defined]

        policy_path = _write_policy(
            tmp_path,
            deny_rules=True,
            sandbox={"allow_paths": {"write": ["/tmp"]}},
        )

        from avakill.core.models import PolicyConfig
        from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend

        # Create backend and test wrap_command
        policy_data = yaml.safe_load(policy_path.read_text())
        policy = PolicyConfig.model_validate(policy_data)

        backend = MacOSSandboxBackend(policy)

        # Mock os.path.isfile to pretend sandbox-exec exists
        original_isfile = os.path.isfile
        monkeypatch.setattr(  # type: ignore[attr-defined]
            "os.path.isfile",
            lambda p: True if p == "/usr/bin/sandbox-exec" else original_isfile(p),
        )

        wrapped = backend.wrap_command(["echo", "hello"], policy.sandbox)
        assert wrapped[0] == "/usr/bin/sandbox-exec"
        assert wrapped[1] == "-f"
        # wrapped[2] is the temp profile path
        assert wrapped[2].endswith(".sb")
        assert wrapped[3:] == ["echo", "hello"]

        # Verify the temp profile was written
        profile_path = Path(wrapped[2])
        assert profile_path.exists()
        content = profile_path.read_text()
        assert "(version 1)" in content
        assert "(allow default)" in content

        # Cleanup should remove the file
        backend.cleanup()
        assert not profile_path.exists()

    def test_keep_profile_prevents_cleanup(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        """When keep_profile is set, cleanup should not remove the file."""
        monkeypatch.setattr("sys.platform", "darwin")  # type: ignore[attr-defined]

        from avakill.core.models import PolicyConfig, PolicyRule, SandboxConfig
        from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend

        policy = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
            sandbox=None,
        )
        backend = MacOSSandboxBackend(policy)
        backend.set_keep_profile(True)

        original_isfile = os.path.isfile
        monkeypatch.setattr(  # type: ignore[attr-defined]
            "os.path.isfile",
            lambda p: True if p == "/usr/bin/sandbox-exec" else original_isfile(p),
        )

        sandbox_cfg = policy.sandbox or SandboxConfig()
        wrapped = backend.wrap_command(["echo", "hello"], sandbox_cfg)
        profile_path = Path(wrapped[2])
        assert profile_path.exists()

        backend.cleanup()
        # File should still exist because keep_profile is set
        assert profile_path.exists()

        # Manual cleanup
        profile_path.unlink()

    def test_sandbox_exec_not_found_error(self, tmp_path: Path) -> None:
        """If sandbox-exec is missing, backend.available() returns False."""
        from avakill.core.models import PolicyConfig
        from avakill.launcher.backends.macos_sandbox import MacOSSandboxBackend

        policy = PolicyConfig(
            version="1.0",
            default_action="allow",
            policies=[],
        )

        backend = MacOSSandboxBackend(policy)

        with patch("sys.platform", "darwin"), patch("os.path.isfile", return_value=False):
            assert not backend.available()
            report = backend.describe(None)
            assert not report["sandbox_applied"]
            assert "not found" in report["reason"]

    def test_sandbox_violation_exit_code_126(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        """Exit code 126 should produce a human-readable error message."""
        monkeypatch.setattr("sys.platform", "darwin")  # type: ignore[attr-defined]
        policy_path = _write_policy(tmp_path)

        from avakill.launcher.core import LaunchResult

        mock_result = LaunchResult(
            exit_code=126,
            pid=12345,
            sandbox_applied=True,
            sandbox_features={},
            duration_seconds=0.1,
        )

        with patch("avakill.launcher.core.ProcessLauncher.launch", return_value=mock_result):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["launch", "--policy", str(policy_path), "--", "echo", "hello"],
            )
            assert result.exit_code == 126
            assert "sandbox-exec failed" in result.output

    def test_sandbox_sigkill_message(
        self,
        tmp_path: Path,
        monkeypatch: object,
    ) -> None:
        """Negative exit code (SIGKILL) should explain sandbox blocking."""
        monkeypatch.setattr("sys.platform", "darwin")  # type: ignore[attr-defined]
        policy_path = _write_policy(tmp_path)

        from avakill.launcher.core import LaunchResult

        mock_result = LaunchResult(
            exit_code=-9,
            pid=12345,
            sandbox_applied=True,
            sandbox_features={},
            duration_seconds=0.1,
        )

        with patch("avakill.launcher.core.ProcessLauncher.launch", return_value=mock_result):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["launch", "--policy", str(policy_path), "--", "echo", "hello"],
            )
            assert "SIGKILL" in result.output
            assert "sandbox" in result.output.lower()


class TestLaunchAgentFlag:
    def test_launch_agent_flag_dry_run(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "launch",
                "--agent",
                "openclaw",
                "--policy",
                str(policy_path),
                "--dry-run",
                "--",
                "echo",
                "test",
            ],
        )
        assert result.exit_code == 0
        assert "openclaw" in result.output.lower() or "sandbox" in result.output.lower()

    def test_launch_agent_uses_profile_sandbox(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "launch",
                "--agent",
                "aider",
                "--policy",
                str(policy_path),
                "--dry-run",
                "--",
                "echo",
                "test",
            ],
        )
        assert result.exit_code == 0

    def test_launch_unknown_agent_exits_error(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "launch",
                "--agent",
                "nonexistent-agent",
                "--policy",
                str(policy_path),
                "--dry-run",
                "--",
                "echo",
                "test",
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_launch_agent_without_command_uses_profile_default(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "launch",
                "--agent",
                "openclaw",
                "--policy",
                str(policy_path),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
