"""Tests for avakill profile CLI commands."""

from __future__ import annotations

from click.testing import CliRunner

from avakill.cli.profile_cmd import profile


class TestProfileList:
    def test_list_shows_profiles(self):
        runner = CliRunner()
        result = runner.invoke(profile, ["list"])
        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "openclaw" in output_lower
        assert "aider" in output_lower

    def test_list_shows_descriptions(self):
        runner = CliRunner()
        result = runner.invoke(profile, ["list", "--verbose"])
        assert result.exit_code == 0
        assert "Node.js" in result.output or "Python" in result.output


class TestProfileShow:
    def test_show_openclaw(self):
        runner = CliRunner()
        result = runner.invoke(profile, ["show", "openclaw"])
        assert result.exit_code == 0
        assert "openclaw" in result.output.lower()

    def test_show_unknown_agent(self):
        runner = CliRunner()
        result = runner.invoke(profile, ["show", "nonexistent"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_show_displays_protection_modes(self):
        runner = CliRunner()
        result = runner.invoke(profile, ["show", "openclaw"])
        assert result.exit_code == 0
        assert "mcp" in result.output.lower()
