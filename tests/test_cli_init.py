"""Tests for avakill init CLI command."""

from __future__ import annotations

import yaml
from click.testing import CliRunner

from avakill.cli.init_cmd import init


class TestInitModeSelector:
    def test_init_non_interactive_skips_mode_selector(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--output", "test.yaml"])
        assert result.exit_code == 0
        assert (tmp_path / "test.yaml").exists()

    def test_init_mode_hooks_shows_hook_steps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init, ["--template", "default", "--mode", "hooks", "--output", "test.yaml"]
        )
        assert result.exit_code == 0
        assert "hook" in result.output.lower()

    def test_init_mode_launch_shows_launch_steps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init, ["--template", "default", "--mode", "launch", "--output", "test.yaml"]
        )
        assert result.exit_code == 0
        assert "launch" in result.output.lower()

    def test_init_mode_mcp_shows_mcp_steps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init, ["--template", "default", "--mode", "mcp", "--output", "test.yaml"]
        )
        assert result.exit_code == 0
        assert "mcp" in result.output.lower()

    def test_init_mode_all_shows_all_next_steps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init, ["--template", "default", "--mode", "all", "--output", "test.yaml"]
        )
        assert result.exit_code == 0
        assert "hook" in result.output.lower()
        assert "launch" in result.output.lower()
        assert "mcp" in result.output.lower()

    def test_init_no_mode_still_works(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--output", "test.yaml"])
        assert result.exit_code == 0
        assert (tmp_path / "test.yaml").exists()


class TestInitScan:
    def test_scan_detects_env_file_and_adds_rule(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names

    def test_scan_prints_summary(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        assert ".env" in result.output

    def test_scan_with_no_sensitive_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        assert (tmp_path / "test.yaml").exists()

    def test_scan_rules_come_before_template_rules(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        env_idx = rule_names.index("protect-env-files")
        template_idx = rule_names.index("block-destructive-ops")
        assert env_idx < template_idx

    def test_no_scan_flag_skips_scanning(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" not in rule_names

    def test_scan_detects_multiple_categories(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("SECRET=abc")
        (tmp_path / "server.pem").write_text("---BEGIN---")
        (tmp_path / "app.sqlite").write_text("")
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "default", "--scan", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        rule_names = [r["name"] for r in policy["policies"]]
        assert "protect-env-files" in rule_names
        assert "protect-crypto-files" in rule_names
        assert "protect-database-files" in rule_names
