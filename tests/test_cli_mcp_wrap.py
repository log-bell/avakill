"""Tests for mcp-wrap, mcp-unwrap, and mcp-proxy CLI commands."""

from __future__ import annotations

from click.testing import CliRunner

from avakill.cli.mcp_proxy_cmd import mcp_proxy
from avakill.cli.mcp_wrap_cmd import mcp_unwrap, mcp_wrap

# ---------------------------------------------------------------------------
# TestMCPWrapCLI
# ---------------------------------------------------------------------------


class TestMCPWrapCLI:
    """Test the mcp-wrap and mcp-unwrap CLI commands."""

    def test_wrap_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(mcp_wrap, ["--help"])
        assert result.exit_code == 0
        assert "Wrap MCP server configs" in result.output
        assert "--agent" in result.output
        assert "--policy" in result.output
        assert "--dry-run" in result.output

    def test_unwrap_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(mcp_unwrap, ["--help"])
        assert result.exit_code == 0
        assert "Restore original MCP server configs" in result.output
        assert "--agent" in result.output

    def test_wrap_dry_run_shows_changes(self, tmp_path, monkeypatch) -> None:
        """--dry-run shows changes without writing."""
        import json

        from avakill.mcp.config import MCP_CONFIG_PATHS

        config_data = {
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "@anthropic/mcp-fs"]},
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))
        monkeypatch.setitem(MCP_CONFIG_PATHS, "claude-desktop", [config_path])

        runner = CliRunner()
        result = runner.invoke(
            mcp_wrap, ["--agent", "claude-desktop", "--dry-run", "--policy", "avakill.yaml"]
        )
        assert result.exit_code == 0
        assert "wrapped" in result.output
        assert "Dry run" in result.output

        # Verify file unchanged
        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["fs"]["command"] == "npx"

    def test_wrap_no_configs_found(self, tmp_path, monkeypatch) -> None:
        from avakill.mcp.config import MCP_CONFIG_PATHS

        monkeypatch.setitem(MCP_CONFIG_PATHS, "claude-desktop", [tmp_path / "nonexistent.json"])

        runner = CliRunner()
        result = runner.invoke(mcp_wrap, ["--agent", "claude-desktop"])
        assert result.exit_code == 0
        assert "No MCP configs found" in result.output


# ---------------------------------------------------------------------------
# TestMCPProxyCLI — HTTP mode
# ---------------------------------------------------------------------------


class TestMCPProxyCLI:
    """Test the mcp-proxy CLI command with HTTP mode options."""

    def test_proxy_help_shows_http_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(mcp_proxy, ["--help"])
        assert result.exit_code == 0
        assert "--upstream-url" in result.output
        assert "--listen-port" in result.output
        assert "--upstream-cmd" in result.output

    def test_proxy_no_upstream_exits_1(self) -> None:
        """Neither --upstream-cmd nor --upstream-url → error."""
        runner = CliRunner()
        result = runner.invoke(mcp_proxy, ["--policy", "avakill.yaml"])
        assert result.exit_code == 1

    def test_proxy_http_mode_missing_policy_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            mcp_proxy,
            ["--upstream-url", "http://localhost:3000", "--policy", "nonexistent.yaml"],
        )
        assert result.exit_code == 1

    def test_proxy_stdio_mode_missing_policy_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            mcp_proxy,
            ["--upstream-cmd", "echo", "--policy", "nonexistent.yaml"],
        )
        assert result.exit_code == 1
