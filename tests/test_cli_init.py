"""Tests for avakill init CLI command."""

from __future__ import annotations

import yaml
from click.testing import CliRunner

from avakill.cli.init_cmd import init
from avakill.core.models import PolicyConfig


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


class TestInitRuleFlags:
    """Tests for --rule, --all-rules, --list-rules, --default-action flags."""

    def test_rule_flag_produces_policy_with_that_rule(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--rule", "block-dangerous-shell", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        names = [r["name"] for r in policy["policies"]]
        assert "block-dangerous-shell" in names
        # Base rules always present
        assert "block-catastrophic-shell" in names
        PolicyConfig.model_validate(policy)

    def test_multiple_rule_flags(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init,
            [
                "--rule",
                "block-dangerous-shell",
                "--rule",
                "rate-limit-web-search",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        names = [r["name"] for r in policy["policies"]]
        assert "block-dangerous-shell" in names
        assert "rate-limit-web-search" in names

    def test_all_rules_includes_everything(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--all-rules", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        names = [r["name"] for r in policy["policies"]]
        # Should have all 28 optional (9 T1 + 14 T2 + 3 T3 + 2 T5) + 3 base + log-all = 32
        assert len(names) == 32
        PolicyConfig.model_validate(policy)

    def test_list_rules_prints_catalog(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--list-rules"])
        assert result.exit_code == 0
        assert "block-dangerous-shell" in result.output
        assert "block-catastrophic-shell" in result.output
        assert "rate-limit-web-search" in result.output

    def test_rule_plus_template_errors(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init,
            [
                "--rule",
                "block-dangerous-shell",
                "--template",
                "hooks",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower()

    def test_template_hooks_still_works(self, tmp_path, monkeypatch):
        """Backward compat: --template hooks produces the old hooks template."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--template", "hooks", "--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert policy["default_action"] == "allow"
        # The hooks template has specific rule names
        names = [r["name"] for r in policy["policies"]]
        assert "block-dangerous-shell" in names

    def test_default_action_deny(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            init,
            [
                "--rule",
                "block-dangerous-shell",
                "--default-action",
                "deny",
                "--output",
                "test.yaml",
            ],
        )
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        assert policy["default_action"] == "deny"
        # No log-all when deny
        names = [r["name"] for r in policy["policies"]]
        assert "log-all" not in names

    def test_unknown_rule_errors(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--rule", "nonexistent-rule", "--output", "test.yaml"])
        assert result.exit_code != 0
        assert "Unknown rule ID" in result.output

    def test_non_interactive_no_flags_uses_defaults(self, tmp_path, monkeypatch):
        """Non-TTY with no flags uses default_on rules."""
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(init, ["--output", "test.yaml"])
        assert result.exit_code == 0
        policy = yaml.safe_load((tmp_path / "test.yaml").read_text())
        names = [r["name"] for r in policy["policies"]]
        # default_on rules should be present
        assert "block-dangerous-shell" in names
        assert "block-destructive-sql" in names
        assert "block-destructive-tools" in names
        PolicyConfig.model_validate(policy)
