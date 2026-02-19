"""Tests for the launch CLI command."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from avakill.cli.main import cli


def _write_policy(tmp_path: Path, sandbox: dict | None = None) -> Path:
    """Write a minimal policy YAML and return its path."""
    data: dict = {
        "version": "1.0",
        "default_action": "allow",
        "policies": [
            {"name": "allow-all", "tools": ["*"], "action": "allow"},
        ],
    }
    if sandbox:
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

    def test_launch_dry_run_shows_sandbox_info(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli, ["launch", "--policy", str(policy_path), "--dry-run", "--", "echo", "hello"]
        )
        assert result.exit_code == 0
        assert "Sandbox dry-run report" in result.output
        assert "Features:" in result.output

    def test_launch_echo_returns_0(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["launch", "--policy", str(policy_path), "--", "echo", "hello"])
        assert result.exit_code == 0

    def test_launch_false_returns_1(self, tmp_path: Path) -> None:
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

    def test_launch_missing_command_exits_2(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["launch", "--policy", str(policy_path)])
        assert result.exit_code == 2  # Click exits 2 for missing required arg
