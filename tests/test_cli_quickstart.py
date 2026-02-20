"""Tests for avakill quickstart CLI command."""

from __future__ import annotations

from unittest.mock import patch

import yaml
from click.testing import CliRunner

from avakill.cli.quickstart_cmd import quickstart


class TestQuickstartNonInteractive:
    def test_generates_policy_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--no-scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        assert (tmp_path / "test.yaml").exists()

    def test_moderate_uses_default_template(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--no-scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert policy["default_action"] == "deny"

    def test_strict_uses_strict_template(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "strict",
                "--no-scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert any(r["name"] == "allow-reads-only" for r in policy["policies"])

    def test_permissive_uses_hooks_template(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "permissive",
                "--no-scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert policy["default_action"] == "allow"

    def test_validation_runs_and_passes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--no-scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        assert "Validation passed" in result.output

    def test_shows_next_steps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--no-scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        assert "Next steps" in result.output


class TestQuickstartWithScan:
    def test_scan_adds_rules_for_env(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names

    def test_scan_prints_detected_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--scan",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        assert ".env" in result.output


class TestQuickstartWithHookInstall:
    def test_installs_hook_for_agent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_path = tmp_path / "claude-settings.json"
        runner = CliRunner()
        with patch("avakill.cli.quickstart_cmd.install_hook") as mock_install:
            mock_install.return_value = type(
                "R",
                (),
                {
                    "config_path": config_path,
                    "command": "avakill-hook-claude-code",
                    "warnings": [],
                    "smoke_test_passed": True,
                },
            )()
            result = runner.invoke(
                quickstart,
                [
                    "--agent",
                    "claude-code",
                    "--level",
                    "moderate",
                    "--no-scan",
                    "--output",
                    "test.yaml",
                ],
            )
        assert result.exit_code == 0
        mock_install.assert_called_once_with("claude-code")
        assert "Hook installed" in result.output

    def test_agent_none_skips_hook_install(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        with patch("avakill.cli.quickstart_cmd.install_hook") as mock_install:
            result = runner.invoke(
                quickstart,
                [
                    "--agent",
                    "none",
                    "--level",
                    "moderate",
                    "--no-scan",
                    "--output",
                    "test.yaml",
                ],
            )
        assert result.exit_code == 0
        mock_install.assert_not_called()


class TestQuickstartHelp:
    def test_help_shows_usage(self):
        runner = CliRunner()
        result = runner.invoke(quickstart, ["--help"])
        assert result.exit_code == 0
        assert "quickstart" in result.output.lower() or "Quickstart" in result.output


class TestQuickstartIntegration:
    """End-to-end test combining scan + policy generation + validation."""

    def test_full_flow_with_scan(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Set up a realistic project
        (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost/db")
        (tmp_path / ".env.local").write_text("DEBUG=true")
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'")
        (tmp_path / "credentials.json").write_text("{}")
        (tmp_path / "app.sqlite").write_text("")

        runner = CliRunner()
        result = runner.invoke(
            quickstart,
            [
                "--agent",
                "none",
                "--level",
                "moderate",
                "--scan",
                "--output",
                "avakill.yaml",
            ],
        )
        assert result.exit_code == 0
        assert "Validation passed" in result.output

        # Verify the generated policy is valid and has scan rules
        policy = yaml.safe_load((tmp_path / "avakill.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names
        assert "protect-credential-files" in rule_names
        assert "protect-database-files" in rule_names

        # Verify scan rules come before template rules
        env_idx = rule_names.index("protect-env-files")
        first_template = rule_names.index("block-destructive-ops")
        assert env_idx < first_template
