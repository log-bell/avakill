"""MCP config discovery and parsing for agent interception.

Discovers and parses MCP server configurations from supported AI agents
(Claude Desktop, Cursor, Windsurf, Cline, Continue.dev).  Used by
``mcp-wrap`` to rewrite configs so all MCP traffic routes through AvaKill.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

logger = logging.getLogger("avakill.mcp.config")

# Agent MCP config file locations (platform-specific)
MCP_CONFIG_PATHS: dict[str, list[Path]] = {
    "claude-desktop": [
        Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",  # macOS
        Path.home() / ".config/claude/claude_desktop_config.json",  # Linux
        Path.home() / "AppData/Roaming/Claude/claude_desktop_config.json",  # Windows
    ],
    "cursor": [
        Path(".cursor/mcp.json"),
        Path.home() / ".cursor/mcp.json",
    ],
    "windsurf": [
        Path(".windsurf/mcp.json"),
        Path.home() / ".codeium/windsurf/mcp.json",
    ],
    "cline": [
        Path(".vscode/cline_mcp_settings.json"),
    ],
    "continue": [
        Path(".continue/config.json"),
    ],
    "openclaw": [
        Path.home() / ".openclaw/mcp.json",
    ],
}


class MCPServerEntry(BaseModel):
    """A single MCP server entry from an agent's config."""

    name: str
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] | None = None
    transport: Literal["stdio", "sse", "streamable-http"] = "stdio"
    url: str | None = None  # For HTTP transport


class MCPConfig(BaseModel):
    """Parsed MCP configuration from an agent's config file."""

    agent: str
    config_path: Path
    servers: list[MCPServerEntry]


def discover_mcp_configs(agent: str | None = None) -> list[MCPConfig]:
    """Find all agent MCP config files on this system.

    Args:
        agent: If specified, only search for this agent's config.
               If ``None``, search for all known agents.

    Returns:
        A list of parsed :class:`MCPConfig` for each found config file.
    """
    agents = [agent] if agent else list(MCP_CONFIG_PATHS)
    results: list[MCPConfig] = []

    for agent_name in agents:
        paths = MCP_CONFIG_PATHS.get(agent_name, [])
        for path in paths:
            if path.exists():
                try:
                    config = parse_mcp_config(agent_name, path)
                    results.append(config)
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to parse %s config at %s", agent_name, path)
                break  # Use first found path per agent

    return results


def parse_mcp_config(agent: str, config_path: Path) -> MCPConfig:
    """Parse an agent's MCP config file into structured entries.

    Supports the common MCP config format where servers are specified
    under a ``"mcpServers"`` key (Claude Desktop, Cursor, Windsurf)
    or a ``"mcpSettings"`` / ``"servers"`` key (Cline, Continue).
    """
    raw = json.loads(config_path.read_text())
    servers: list[MCPServerEntry] = []

    # Claude Desktop, Cursor, Windsurf: {"mcpServers": {"name": {...}}}
    mcp_servers: dict[str, Any] = raw.get("mcpServers", {})

    # Cline: {"mcpServers": {...}} (same format)
    # Continue: may use different key
    if not mcp_servers:
        mcp_servers = raw.get("servers", {})

    for name, entry in mcp_servers.items():
        if not isinstance(entry, dict):
            continue
        server = MCPServerEntry(
            name=name,
            command=entry.get("command", ""),
            args=entry.get("args", []),
            env=entry.get("env"),
            transport=_detect_transport(entry),
            url=entry.get("url"),
        )
        servers.append(server)

    return MCPConfig(agent=agent, config_path=config_path, servers=servers)


def is_already_wrapped(entry: MCPServerEntry) -> bool:
    """Check if an MCP server entry is already wrapped by AvaKill.

    A server is considered wrapped if its command is ``avakill``
    and its args include ``mcp-proxy``.
    """
    if entry.command == "avakill" and "mcp-proxy" in entry.args:
        return True
    # Check for avakill-shim binary
    if "avakill-shim" in entry.command:
        return True
    # Also check for module invocation: python -m avakill mcp-proxy
    return "avakill" in entry.command and "mcp-proxy" in entry.args


def _detect_transport(entry: dict[str, Any]) -> Literal["stdio", "sse", "streamable-http"]:
    """Detect the transport type from a raw config entry."""
    transport: str = entry.get("transport", "stdio")
    if transport == "sse":
        return "sse"
    if transport == "streamable-http":
        return "streamable-http"
    if entry.get("url"):
        return "streamable-http"
    return "stdio"
