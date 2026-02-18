"""Tests for the enforce CLI command group."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from avakill.cli.main import cli


def _make_policy_file(tmp_path: Path) -> Path:
    """Create a temporary policy file with deny rules."""
    policy = tmp_path / "avakill.yaml"
    policy.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: deny-write\n"
        "    tools: [file_write]\n"
        "    action: deny\n"
        "  - name: deny-exec\n"
        "    tools: [shell_execute]\n"
        "    action: deny\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
    )
    return policy


class TestEnforceCLI:
    """Tests for the enforce command group."""

    def test_enforce_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "--help"])
        assert result.exit_code == 0
        assert "OS-level enforcement" in result.output

    def test_landlock_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "landlock", "--help"])
        assert result.exit_code == 0
        assert "Landlock" in result.output
        assert "--dry-run" in result.output
        assert "--policy" in result.output

    def test_sandbox_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "sandbox", "--help"])
        assert result.exit_code == 0
        assert "sandbox-exec" in result.output
        assert "--output" in result.output

    def test_tetragon_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "tetragon", "--help"])
        assert result.exit_code == 0
        assert "Tetragon" in result.output
        assert "--output" in result.output

    def test_landlock_dry_run(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)

        with patch(
            "avakill.enforcement.landlock.LandlockEnforcer.available",
            return_value=True,
        ):
            result = runner.invoke(
                cli,
                ["enforce", "landlock", "--policy", str(policy), "--dry-run"],
            )

        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        assert "deny-write" in result.output

    def test_sandbox_generates_profile(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        output = tmp_path / "profile.sb"

        with patch(
            "avakill.enforcement.sandbox_exec.SandboxExecEnforcer.available",
            return_value=True,
        ):
            result = runner.invoke(
                cli,
                [
                    "enforce",
                    "sandbox",
                    "--policy",
                    str(policy),
                    "-o",
                    str(output),
                ],
            )

        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text()
        assert "(version 1)" in content
        assert "(deny file-write-data)" in content

    def test_tetragon_generates_policy(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        output = tmp_path / "tetragon.yaml"

        result = runner.invoke(
            cli,
            [
                "enforce",
                "tetragon",
                "--policy",
                str(policy),
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text()
        assert "cilium.io/v1alpha1" in content

    def test_landlock_not_available_shows_error(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)

        with patch(
            "avakill.enforcement.landlock.LandlockEnforcer.available",
            return_value=False,
        ):
            result = runner.invoke(
                cli,
                ["enforce", "landlock", "--policy", str(policy)],
            )

        assert result.exit_code == 1
        assert "not available" in result.output.lower()

    def test_sandbox_not_available_shows_error(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)
        output = tmp_path / "profile.sb"

        with patch(
            "avakill.enforcement.sandbox_exec.SandboxExecEnforcer.available",
            return_value=False,
        ):
            result = runner.invoke(
                cli,
                [
                    "enforce",
                    "sandbox",
                    "--policy",
                    str(policy),
                    "-o",
                    str(output),
                ],
            )

        assert result.exit_code == 1
        assert "macos" in result.output.lower()

    def test_landlock_missing_policy_exits_1(self) -> None:
        runner = CliRunner()

        with patch(
            "avakill.enforcement.landlock.LandlockEnforcer.available",
            return_value=True,
        ):
            result = runner.invoke(
                cli,
                ["enforce", "landlock", "--policy", "/nonexistent/policy.yaml"],
            )

        assert result.exit_code == 1

    def test_tetragon_missing_policy_exits_1(self) -> None:
        runner = CliRunner()

        result = runner.invoke(
            cli,
            [
                "enforce",
                "tetragon",
                "--policy",
                "/nonexistent/policy.yaml",
                "-o",
                "/tmp/out.yaml",
            ],
        )

        assert result.exit_code == 1

    def test_sandbox_output_required(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "sandbox", "--policy", "x.yaml"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_tetragon_output_required(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "tetragon", "--policy", "x.yaml"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()
