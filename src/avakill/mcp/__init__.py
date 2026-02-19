"""MCP (Model Context Protocol) transparent proxy for tool call interception."""

from avakill.mcp.config import MCPConfig, MCPServerEntry, discover_mcp_configs
from avakill.mcp.proxy import MCPHTTPProxy, MCPProxyServer

__all__ = [
    "MCPConfig",
    "MCPHTTPProxy",
    "MCPProxyServer",
    "MCPServerEntry",
    "discover_mcp_configs",
]
