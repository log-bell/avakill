"""Tests for the enforce CLI command group."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli
from avakill.core.models import (
    PolicyConfig,
    PolicyRule,
    SandboxConfig,
    SandboxNetworkRules,
    SandboxPathRules,
)
from avakill.enforcement.sandbox_exec import SandboxExecEnforcer, SandboxProfileError


def _make_policy_file(tmp_path: Path) -> Path:
    """Create a temporary policy file with deny rules and sandbox section."""
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
        "sandbox:\n"
        "  allow_paths:\n"
        "    read:\n"
        "      - /usr\n"
        "      - /bin\n"
        "    write:\n"
        "      - /tmp\n"
        "      - /Users/test/project\n"
        "    execute:\n"
        "      - /usr/bin/python3\n"
        "      - /usr/bin/git\n"
    )
    return policy


def _make_file_only_policy(tmp_path: Path) -> Path:
    """Create a policy with only file deny rules (no exec/network)."""
    policy = tmp_path / "avakill.yaml"
    policy.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: deny-write\n"
        "    tools: [file_write]\n"
        "    action: deny\n"
        "  - name: allow-read\n"
        "    tools: [file_read]\n"
        "    action: allow\n"
        "sandbox:\n"
        "  allow_paths:\n"
        "    write:\n"
        "      - /tmp\n"
    )
    return policy


def _make_no_sandbox_exec_policy(tmp_path: Path) -> Path:
    """Create a policy that denies shell_execute with NO execute allowlist."""
    policy = tmp_path / "avakill.yaml"
    policy.write_text(
        "version: '1.0'\n"
        "default_action: deny\n"
        "policies:\n"
        "  - name: deny-exec\n"
        "    tools: [shell_execute]\n"
        "    action: deny\n"
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
        assert "--dry-run" in result.output

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
        assert "(allow default)" in content
        # Must have scoped deny, NOT bare global deny
        assert "(deny file-write*" in content
        assert "require-not" in content

    def test_sandbox_dry_run(self, tmp_path: Path) -> None:
        runner = CliRunner()
        policy = _make_policy_file(tmp_path)

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
                    "--dry-run",
                ],
            )

        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        assert "(version 1)" in result.output
        assert "(allow default)" in result.output

    def test_sandbox_output_required_without_dry_run(self) -> None:
        runner = CliRunner()
        with patch(
            "avakill.enforcement.sandbox_exec.SandboxExecEnforcer.available",
            return_value=True,
        ):
            result = runner.invoke(cli, ["enforce", "sandbox", "--policy", "x.yaml"])
        assert result.exit_code != 0

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

    def test_tetragon_output_required(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["enforce", "tetragon", "--policy", "x.yaml"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()


class TestSandboxExecEnforcer:
    """Unit tests for SandboxExecEnforcer.generate_profile()."""

    def _config_with_sandbox(
        self,
        rules: list[PolicyRule],
        sandbox: SandboxConfig | None = None,
    ) -> PolicyConfig:
        return PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=rules,
            sandbox=sandbox,
        )

    def test_profile_starts_with_allow_default(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(write=["/tmp"]),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        assert "(version 1)" in profile
        assert "(allow default)" in profile

    def test_allow_paths_appear_as_exceptions(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(write=["/tmp", "/Users/test/project"]),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        assert "require-not" in profile
        assert '(subpath "/tmp")' in profile
        assert '(subpath "/Users/test/project")' in profile

    def test_no_global_process_exec_deny(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-exec", tools=["shell_execute"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(execute=["/usr/bin/python3"]),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        # Should have scoped process-exec deny, not bare global
        lines = profile.split("\n")
        for i, line in enumerate(lines):
            if line.strip() == "(deny process-exec)":
                pytest.fail(
                    f"Found bare global (deny process-exec) at line {i + 1}. "
                    "Expected scoped denial with literal paths."
                )

        # Should contain scoped process-exec with literal shell paths
        assert "(deny process-exec" in profile
        assert '(literal "/bin/sh")' in profile
        assert '(literal "/bin/bash")' in profile

    def test_file_only_deny_no_network_or_process(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(write=["/tmp"]),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        assert "file-write" in profile
        assert "process-exec" not in profile
        assert "network-outbound" not in profile

    def test_network_deny_scoped_with_allowlist(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-network", tools=["web_fetch"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_network=SandboxNetworkRules(
                    connect=["api.anthropic.com:443"],
                ),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        assert "(deny network-outbound" in profile
        assert "require-not" in profile
        assert '(remote tcp "api.anthropic.com:443")' in profile
        assert '(remote tcp "localhost:*")' in profile

    def test_network_deny_allows_localhost_even_without_allowlist(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-network", tools=["web_fetch"], action="deny"),
            ],
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        assert "(deny network-outbound" in profile
        assert '(remote tcp "localhost:*")' in profile

    def test_no_deny_rules_produces_minimal_profile(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
            ],
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        assert "(allow default)" in profile
        assert "No deny rules found" in profile
        assert "(deny" not in profile

    def test_safety_check_refuses_global_process_exec(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-exec", tools=["shell_execute"], action="deny"),
            ],
            # No sandbox section — no execute allowlist
        )
        enforcer = SandboxExecEnforcer()

        with pytest.raises(SandboxProfileError, match="globally deny process-exec"):
            enforcer.generate_profile(config)

    def test_profile_structure_valid_sbpl(self) -> None:
        """Round-trip: generate from known policy, verify SBPL structure."""
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
                PolicyRule(name="deny-exec", tools=["shell_execute"], action="deny"),
                PolicyRule(name="deny-net", tools=["web_fetch"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(
                    write=["/tmp", "/Users/test/output"],
                    execute=["/usr/bin/python3", "/usr/bin/git"],
                ),
                allow_network=SandboxNetworkRules(
                    connect=["api.anthropic.com:443"],
                ),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        # Structural checks
        assert profile.startswith("(version 1)")
        assert "(allow default)" in profile

        # Balanced parentheses
        open_count = profile.count("(")
        close_count = profile.count(")")
        assert open_count == close_count, (
            f"Unbalanced parens: {open_count} open vs {close_count} close"
        )

        # All three categories present
        assert "file-write" in profile
        assert "process-exec" in profile
        assert "network-outbound" in profile

        # Allowed paths are exceptions
        assert '(subpath "/tmp")' in profile
        assert '(subpath "/Users/test/output")' in profile
        assert '(remote tcp "api.anthropic.com:443")' in profile

    def test_system_write_paths_always_allowed(self) -> None:
        config = self._config_with_sandbox(
            rules=[
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
            sandbox=SandboxConfig(
                allow_paths=SandboxPathRules(write=["/tmp"]),
            ),
        )
        enforcer = SandboxExecEnforcer()
        profile = enforcer.generate_profile(config)

        # System paths like /private/var/folders should be in exceptions
        assert '(subpath "/private/var/folders")' in profile
        assert '(subpath "/dev/null")' in profile
