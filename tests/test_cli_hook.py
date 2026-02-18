"""Tests for the hook CLI commands."""

from __future__ import annotations

from click.testing import CliRunner

from avakill.cli.main import cli


class TestHookCLI:
    """Test the hook CLI command group."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_hook_help(self) -> None:
        result = self.runner.invoke(cli, ["hook", "--help"])
        assert result.exit_code == 0
        assert "Manage agent hook integrations" in result.output

    def test_install_help(self) -> None:
        result = self.runner.invoke(cli, ["hook", "install", "--help"])
        assert result.exit_code == 0
        assert "--agent" in result.output

    def test_uninstall_help(self) -> None:
        result = self.runner.invoke(cli, ["hook", "uninstall", "--help"])
        assert result.exit_code == 0
        assert "--agent" in result.output

    def test_list_help(self) -> None:
        result = self.runner.invoke(cli, ["hook", "list", "--help"])
        assert result.exit_code == 0
        assert "detected agents" in result.output.lower() or "hook" in result.output.lower()

    def test_list_shows_agents(self, monkeypatch) -> None:
        """The list command should show all four agent names."""
        result = self.runner.invoke(cli, ["hook", "list"])
        assert result.exit_code == 0
        assert "claude-code" in result.output
        assert "gemini-cli" in result.output
        assert "cursor" in result.output
        assert "windsurf" in result.output
