"""Tests for MCP config discovery and parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from avakill.mcp.config import (
    MCP_CONFIG_PATHS,
    MCPServerEntry,
    discover_mcp_configs,
    is_already_wrapped,
    parse_mcp_config,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def claude_desktop_config(tmp_path: Path) -> Path:
    """Create a Claude Desktop MCP config file."""
    config = {
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@anthropic/mcp-fs", "/path"],
            },
            "db": {
                "command": "python",
                "args": ["db_server.py"],
                "env": {"DB_URL": "sqlite:///test.db"},
            },
        }
    }
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text(json.dumps(config))
    return config_path


@pytest.fixture()
def cursor_config(tmp_path: Path) -> Path:
    """Create a Cursor MCP config file."""
    config = {
        "mcpServers": {
            "code-tools": {
                "command": "node",
                "args": ["code-tools-server.js"],
            }
        }
    }
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps(config))
    return config_path


# ---------------------------------------------------------------------------
# TestMCPConfigDiscovery
# ---------------------------------------------------------------------------


class TestMCPConfigDiscovery:
    """Test discovery of MCP config files across agents."""

    def test_discover_finds_claude_desktop_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = {
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "@anthropic/mcp-fs"]},
            }
        }
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(json.dumps(config))

        monkeypatch.setitem(MCP_CONFIG_PATHS, "claude-desktop", [config_path])
        results = discover_mcp_configs(agent="claude-desktop")
        assert len(results) == 1
        assert results[0].agent == "claude-desktop"
        assert len(results[0].servers) == 1

    def test_discover_finds_cursor_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = {
            "mcpServers": {
                "tools": {"command": "node", "args": ["server.js"]},
            }
        }
        config_path = tmp_path / "mcp.json"
        config_path.write_text(json.dumps(config))

        monkeypatch.setitem(MCP_CONFIG_PATHS, "cursor", [config_path])
        results = discover_mcp_configs(agent="cursor")
        assert len(results) == 1
        assert results[0].agent == "cursor"

    def test_discover_returns_empty_when_none_exist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(MCP_CONFIG_PATHS, "claude-desktop", [tmp_path / "nonexistent.json"])
        results = discover_mcp_configs(agent="claude-desktop")
        assert results == []


# ---------------------------------------------------------------------------
# TestMCPConfigParsing
# ---------------------------------------------------------------------------


class TestMCPConfigParsing:
    """Test parsing of MCP config files."""

    def test_parse_claude_desktop_config(self, claude_desktop_config: Path) -> None:
        config = parse_mcp_config("claude-desktop", claude_desktop_config)
        assert config.agent == "claude-desktop"
        assert len(config.servers) == 2
        names = {s.name for s in config.servers}
        assert names == {"fs", "db"}

    def test_parse_cursor_config(self, cursor_config: Path) -> None:
        config = parse_mcp_config("cursor", cursor_config)
        assert config.agent == "cursor"
        assert len(config.servers) == 1
        assert config.servers[0].name == "code-tools"

    def test_parse_empty_servers_list(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"mcpServers": {}}))
        config = parse_mcp_config("test", config_path)
        assert config.servers == []

    def test_parse_server_with_env_vars(self, claude_desktop_config: Path) -> None:
        config = parse_mcp_config("claude-desktop", claude_desktop_config)
        db_server = next(s for s in config.servers if s.name == "db")
        assert db_server.env == {"DB_URL": "sqlite:///test.db"}

    def test_parse_server_with_http_transport(self, tmp_path: Path) -> None:
        config_data = {
            "mcpServers": {
                "api": {
                    "command": "",
                    "url": "http://localhost:3000/mcp",
                    "transport": "streamable-http",
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config_data))
        config = parse_mcp_config("test", config_path)
        assert config.servers[0].transport == "streamable-http"
        assert config.servers[0].url == "http://localhost:3000/mcp"


# ---------------------------------------------------------------------------
# TestIsAlreadyWrapped
# ---------------------------------------------------------------------------


class TestIsAlreadyWrapped:
    """Test detection of already-wrapped MCP server entries."""

    def test_unwrapped_entry_returns_false(self) -> None:
        entry = MCPServerEntry(name="fs", command="npx", args=["-y", "@anthropic/mcp-fs"])
        assert is_already_wrapped(entry) is False

    def test_wrapped_entry_returns_true(self) -> None:
        entry = MCPServerEntry(
            name="fs",
            command="avakill",
            args=["mcp-proxy", "--policy", "avakill.yaml", "--upstream-cmd", "npx"],
        )
        assert is_already_wrapped(entry) is True

    def test_double_wrap_detection(self) -> None:
        """Wrapping an already-wrapped entry should be detected."""
        entry = MCPServerEntry(
            name="fs",
            command="avakill",
            args=[
                "mcp-proxy",
                "--upstream-cmd",
                "avakill",
                "--upstream-args",
                "mcp-proxy --upstream-cmd npx",
            ],
        )
        assert is_already_wrapped(entry) is True

    def test_python_module_invocation_detected(self) -> None:
        entry = MCPServerEntry(
            name="fs",
            command="python",
            args=["-m", "avakill", "mcp-proxy", "--upstream-cmd", "npx"],
        )
        assert is_already_wrapped(entry) is False  # command is "python", not "avakill"
