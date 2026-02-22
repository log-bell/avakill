"""Tests for MCP config wrapping and unwrapping."""

from __future__ import annotations

import json
from pathlib import Path

from avakill.mcp.config import MCPConfig, MCPServerEntry, is_already_wrapped
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
        assert is_already_wrapped(server)
        # Go shim format: [flags..., "--", cmd, args...]
        assert "--" in server.args
        sep_idx = server.args.index("--")
        assert server.args[sep_idx + 1] == "npx"

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
        assert "DB_URL" in wrapped.servers[0].env
        assert wrapped.servers[0].env["DB_URL"] == "sqlite:///test.db"

    def test_wrap_with_daemon_flag(self) -> None:
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(name="fs", command="npx", args=["server.js"]),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="avakill.yaml", daemon=True)
        args = wrapped.servers[0].args
        # Go shim uses --socket, Python fallback uses --daemon
        assert "--daemon" in args or "--socket" in args

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
        assert all(is_already_wrapped(s) for s in wrapped.servers)

    def test_wrap_uses_double_dash_separator(self) -> None:
        """Wrapped config should use -- to separate shim flags from upstream."""
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
        assert "--" in server.args, "wrapped args should contain -- separator"
        sep_idx = server.args.index("--")
        # Everything after -- is the original command + args
        assert server.args[sep_idx + 1] == "npx"
        assert server.args[sep_idx + 2 :] == ["-y", "@anthropic/mcp-fs", "/path"]

    def test_wrap_preserves_args_with_spaces(self) -> None:
        """Args containing spaces must survive wrap/unwrap round-trip."""
        config = MCPConfig(
            agent="test",
            config_path=Path("/tmp/config.json"),
            servers=[
                MCPServerEntry(
                    name="fs",
                    command="npx",
                    args=["-y", "@anthropic/mcp-fs", "/Users/John Smith/Desktop"],
                ),
            ],
        )
        wrapped = wrap_mcp_config(config, policy="avakill.yaml")
        unwrapped = unwrap_mcp_config(wrapped)
        server = unwrapped.servers[0]
        assert server.command == "npx"
        assert server.args == ["-y", "@anthropic/mcp-fs", "/Users/John Smith/Desktop"]


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
                    command="/usr/local/bin/avakill-shim",
                    args=[
                        "--policy",
                        "/abs/path/avakill.yaml",
                        "--",
                        "npx",
                        "-y",
                        "@anthropic/mcp-fs",
                        "/path",
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

    def test_unwrap_python_fallback_format(self) -> None:
        """Unwrap should still handle the Python mcp-proxy format."""
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
                    command="/usr/local/bin/avakill-shim",
                    args=["--policy", "/tmp/avakill.yaml", "--", "npx", "server.js"],
                ),
            ],
        )
        write_mcp_config(config)

        written = json.loads(config_path.read_text())
        assert "avakill-shim" in written["mcpServers"]["fs"]["command"]

    def test_write_preserves_non_mcp_keys(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {}, "theme": "dark", "version": "1.0"}))

        config = MCPConfig(agent="test", config_path=config_path, servers=[])
        write_mcp_config(config)

        written = json.loads(config_path.read_text())
        assert written["theme"] == "dark"
        assert written["version"] == "1.0"
