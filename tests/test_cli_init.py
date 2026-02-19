"""Tests for avakill init CLI command."""

from __future__ import annotations

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
