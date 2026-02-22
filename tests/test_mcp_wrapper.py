"""Tests for MCP config wrapping and unwrapping."""

from __future__ import annotations

import json
from pathlib import Path

from avakill.mcp.config import MCPConfig, MCPServerEntry
from avakill.mcp.wrapper import unwrap_mcp_config, wrap_mcp_config, write_mcp_config

# ---------------------------------------------------------------------------
# TestWrapMCPConfig
# ---------------------------------------------------------------------------


class TestWrapMCPConfig:
    """Test wrapping MCP server entries to route through AvaKill."""

    def test_wrap_stdio_server(self) -> None:
        config = MCPConfig(
            agent="claude-desktop",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(
                    name="fs",
                    command="npx",
                    args=["-y", "@anthropic/mcp-fs", "/path"],
                ),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="avakill.yaml")
        server = wrapped.servers[0]
        assert server.command == "avakill"
        assert "mcp-proxy" in server.args
        assert "--upstream-cmd" in server.args
        # upstream-cmd may be resolved to an absolute path
        cmd_idx = server.args.index("--upstream-cmd") + 1
        assert "npx" in server.args[cmd_idx]
        assert "--upstream-args" in server.args

    def test_wrap_preserves_env_vars(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(
                    name="db",
                    command="python",
                    args=["server.py"],
                    env={"DB_URL": "sqlite:///test.db"},
                ),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="policy.yaml")
        assert wrapped.servers[0].env == {"DB_URL": "sqlite:///test.db"}

    def test_wrap_with_daemon_flag(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(name="fs", command="npx", args=["server.js"]),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="avakill.yaml", daemon=True)
        assert "--daemon" in wrapped.servers[0].args

    def test_wrap_skips_already_wrapped(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(
                    name="fs",
                    command="avakill",
                    args=["mcp-proxy", "--upstream-cmd", "npx"],
                ),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="avakill.yaml")
        # Should be unchanged
        assert wrapped.servers[0].command == "avakill"
        assert wrapped.servers[0].args == ["mcp-proxy", "--upstream-cmd", "npx"]

    def test_wrap_multiple_servers(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(name="fs", command="npx", args=["fs-server"]),
                MCPServerEntry(name="db", command="python", args=["db-server.py"]),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="avakill.yaml")
        assert len(wrapped.servers) == 2
        assert all(s.command == "avakill" for s in wrapped.servers)


# ---------------------------------------------------------------------------
# TestUnwrapMCPConfig
# ---------------------------------------------------------------------------


class TestUnwrapMCPConfig:
    """Test unwrapping to restore original server commands."""

    def test_unwrap_restores_original_command(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(
                    name="fs",
                    command="avakill",
                    args=[
                        "mcp-proxy",
                        "--policy",
                        "avakill.yaml",
                        "--upstream-cmd",
                        "npx",
                        "--upstream-args",
                        "-y @anthropic/mcp-fs /path",
                    ],
                ),
            ],
        )
        unwrapped = unwrap_mcp_config(config)
        server = unwrapped.servers[0]
        assert server.command == "npx"
        assert server.args == ["-y", "@anthropic/mcp-fs", "/path"]

    def test_unwrap_non_wrapped_is_noop(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(name="fs", command="npx", args=["fs-server"]),
            ],
        )
        unwrapped = unwrap_mcp_config(config)
        assert unwrapped.servers[0].command == "npx"
        assert unwrapped.servers[0].args == ["fs-server"]


# ---------------------------------------------------------------------------
# TestWriteMCPConfig
# ---------------------------------------------------------------------------


class TestWriteMCPConfig:
    """Test writing modified configs back to disk."""

    def test_write_creates_backup(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {}}))

        config = MCPConfig(agent="test", config_path=config_path, servers=[])
        write_mcp_config(config)

        backup = config_path.with_suffix(".json.bak")
        assert backup.exists()

    def test_write_overwrites_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(
            json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["server.js"]}}})
        )

        config = MCPConfig(
            agent="test",
            config_path=config_path,
            servers=[
                MCPServerEntry(
                    name="fs",
                    command="avakill",
                    args=["mcp-proxy", "--upstream-cmd", "npx"],
                ),
            ],
        )
        write_mcp_config(config)

        written = json.loads(config_path.read_text())
        assert written["mcpServers"]["fs"]["command"] == "avakill"

    def test_write_preserves_non_mcp_keys(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {}, "theme": "dark", "version": "1.0"}))

        config = MCPConfig(agent="test", config_path=config_path, servers=[])
        write_mcp_config(config)

        written = json.loads(config_path.read_text())
        assert written["theme"] == "dark"
        assert written["version"] == "1.0"
