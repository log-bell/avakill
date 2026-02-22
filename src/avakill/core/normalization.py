"""Tool name normalization with per-agent mappings.

Each AI coding agent uses its own naming convention for tools.
This module provides a canonical namespace so that policies can
be written once and applied uniformly across all agents.

Canonical tool names:
    shell_execute, file_read, file_write, file_edit, file_search,
    file_list, content_search, web_fetch, web_search, agent_spawn
"""

from __future__ import annotations

AGENT_TOOL_MAP: dict[str, dict[str, str]] = {
    "claude-code": {
        "Bash": "shell_execute",
        "Read": "file_read",
        "Write": "file_write",
        "Edit": "file_edit",
        "MultiEdit": "file_edit",
        "Glob": "file_search",
        "Grep": "content_search",
        "WebFetch": "web_fetch",
        "WebSearch": "web_search",
        "Task": "agent_spawn",
        "LS": "file_list",
    },
    "gemini-cli": {
        "run_shell_command": "shell_execute",
        "read_file": "file_read",
        "write_file": "file_write",
        "edit_file": "file_edit",
        "search_files": "file_search",
        "list_files": "file_list",
        "web_search": "web_search",
        "web_fetch": "web_fetch",
    },
    "cursor": {
        "shell_command": "shell_execute",
        "read_file": "file_read",
    },
    "windsurf": {
        "run_command": "shell_execute",
        "write_code": "file_write",
        "read_code": "file_read",
        "mcp_tool": "mcp_tool",
    },
    "openai-codex": {
        "shell": "shell_execute",
        "shell_command": "shell_execute",
        "local_shell": "shell_execute",
        "exec_command": "shell_execute",
        "apply_patch": "file_write",
        "read_file": "file_read",
        "list_dir": "file_list",
        "grep_files": "content_search",
    },
}

# Pre-computed reverse maps: canonical -> agent-native
_REVERSE_MAP: dict[str, dict[str, str]] = {}
for _agent, _mapping in AGENT_TOOL_MAP.items():
    _REVERSE_MAP[_agent] = {v: k for k, v in _mapping.items()}


def normalize_tool_name(tool: str, agent: str | None = None) -> str:
    """Normalize an agent-specific tool name to canonical form.

    MCP tools (``mcp__server__tool`` or ``mcp:server:tool``) pass through
    unchanged.  Unknown tools also pass through.

    Args:
        tool: The agent-native tool name.
        agent: The agent identifier (e.g. ``"claude-code"``).

    Returns:
        The canonical tool name, or the original if no mapping exists.
    """
    if tool.startswith("mcp__") or tool.startswith("mcp:"):
        return tool
    if agent is None:
        return tool
    mapping = AGENT_TOOL_MAP.get(agent)
    if mapping is None:
        return tool
    return mapping.get(tool, tool)


def denormalize_tool_name(canonical: str, agent: str) -> str | None:
    """Reverse lookup: canonical name to agent-native name.

    Args:
        canonical: The canonical tool name (e.g. ``"shell_execute"``).
        agent: The agent identifier.

    Returns:
        The agent-native tool name, or ``None`` if no mapping exists.
    """
    reverse = _REVERSE_MAP.get(agent)
    if reverse is None:
        return None
    return reverse.get(canonical)


class ToolNormalizer:
    """Configurable tool name normalizer with optional custom mappings.

    Args:
        custom_mappings: Optional per-agent overrides or additions
            layered on top of the built-in :data:`AGENT_TOOL_MAP`.
    """

    def __init__(
        self,
        custom_mappings: dict[str, dict[str, str]] | None = None,
    ) -> None:
        # Merge built-in + custom (custom wins on conflict)
        self._map: dict[str, dict[str, str]] = {
            agent: dict(tools) for agent, tools in AGENT_TOOL_MAP.items()
        }
        if custom_mappings:
            for agent, tools in custom_mappings.items():
                if agent in self._map:
                    self._map[agent].update(tools)
                else:
                    self._map[agent] = dict(tools)

        # Pre-compute reverse
        self._reverse: dict[str, dict[str, str]] = {}
        for agent, mapping in self._map.items():
            self._reverse[agent] = {v: k for k, v in mapping.items()}

    def normalize(self, tool: str, agent: str | None = None) -> str:
        """Normalize an agent-specific tool name to canonical form."""
        if tool.startswith("mcp__") or tool.startswith("mcp:"):
            return tool
        if agent is None:
            return tool
        mapping = self._map.get(agent)
        if mapping is None:
            return tool
        return mapping.get(tool, tool)

    def denormalize(self, canonical: str, agent: str) -> str | None:
        """Reverse lookup: canonical -> agent-native name."""
        reverse = self._reverse.get(agent)
        if reverse is None:
            return None
        return reverse.get(canonical)
