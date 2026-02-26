"""Behavioral classification of tool calls for cross-call correlation (T4).

Stateless tagger that assigns behavioral tags to a ToolCall based on
tool name patterns (fnmatch) and argument content (pre-compiled regexes).
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from avakill.core.models import ToolCall

# ---------------------------------------------------------------------------
# Tool-name patterns for tag classification
# ---------------------------------------------------------------------------

_SHELL_PATTERNS: list[str] = [
    "Bash",
    "shell_execute",
    "run_shell_command",
    "run_command",
    "shell",
    "local_shell",
    "exec_command",
    "shell_*",
    "bash_*",
    "command_*",
]

_READ_PATTERNS: list[str] = [
    "Read",
    "Glob",
    "Grep",
    "LS",
    "grep_files",
    "search_*",
    "get_*",
    "list_*",
    "read_*",
    "query_*",
    "find_*",
    "lookup_*",
    "*_search",
    "*_get",
    "*_list",
    "*_read",
    "*_query",
    "*_find",
    "*_lookup",
]

_NETWORK_PATTERNS: list[str] = [
    "WebFetch",
    "WebSearch",
    "web_fetch",
    "web_search",
    "fetch_*",
    "*_fetch",
]

_DELETE_PATTERNS: list[str] = [
    "delete_*",
    "remove_*",
    "destroy_*",
    "*_delete",
    "*_remove",
    "*_destroy",
]

# ---------------------------------------------------------------------------
# Argument content patterns (pre-compiled regexes)
# ---------------------------------------------------------------------------

_CREDENTIAL_RE = re.compile(
    r"\.env(?:\b|/)|\.ssh/|\.aws/|\.gnupg/|id_rsa|id_ed25519"
    r"|credentials\.json|serviceAccountKey|\.kube/|\.gcloud/|\.azure/",
    re.IGNORECASE,
)

_ENV_READ_RE = re.compile(
    r"printenv|os\.environ|\$SECRET|\$API_KEY|\$TOKEN|\$PASSWORD"
    r"|getenv\(|environ\[",
    re.IGNORECASE,
)

_ENCODE_RE = re.compile(
    r"base64|xxd|openssl\s+enc",
    re.IGNORECASE,
)

_NETWORK_ARGS_RE = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bnetcat\b"
    r"|\bhttp\.client\b|\brequests\.(?:get|post|put)",
    re.IGNORECASE,
)

_CLIPBOARD_RE = re.compile(
    r"\bpbcopy\b|\bxclip\b|\bxsel\b|\bclip\.exe\b",
    re.IGNORECASE,
)

_FILE_DELETE_ARGS_RE = re.compile(
    r"\brm\b|\bunlink\b|\bshred\b",
    re.IGNORECASE,
)


def _matches_any(name: str, patterns: list[str]) -> bool:
    """Check if name matches any of the fnmatch patterns."""
    return any(fnmatch(name, pattern) for pattern in patterns)


def _search_args(args: dict[str, object], pattern: re.Pattern[str]) -> bool:
    """Search all string argument values for a regex match."""
    return any(isinstance(value, str) and pattern.search(value) for value in args.values())


class CallTagger:
    """Assigns behavioral tags to a ToolCall.

    Stateless — can be shared across sessions.
    """

    def tag(self, tool_call: ToolCall) -> frozenset[str]:
        """Return the set of behavioral tags for a tool call."""
        tags: set[str] = set()
        name = tool_call.tool_name
        args = tool_call.arguments

        # Tool-name based tags
        if _matches_any(name, _SHELL_PATTERNS):
            tags.add("shell_exec")
        if _matches_any(name, _READ_PATTERNS):
            tags.add("file_read")
        if _matches_any(name, _NETWORK_PATTERNS):
            tags.add("network_transmit")
        if _matches_any(name, _DELETE_PATTERNS):
            tags.add("file_delete")

        # Argument content based tags
        if _search_args(args, _CREDENTIAL_RE):
            tags.add("credential_read")
        if _search_args(args, _ENV_READ_RE):
            tags.add("env_read")
        if _search_args(args, _ENCODE_RE):
            tags.add("encode")
        if _search_args(args, _NETWORK_ARGS_RE):
            tags.add("network_transmit")
        if _search_args(args, _CLIPBOARD_RE):
            tags.add("clipboard_write")
        if _search_args(args, _FILE_DELETE_ARGS_RE):
            tags.add("file_delete")

        # Inferred composite tags
        if "credential_read" in tags or "env_read" in tags:
            tags.add("secret_access")

        return frozenset(tags)
