"""Hardcoded self-protection rules that run before user-defined policies.

Prevents agents from weakening their own guardrails by detecting tool calls
that target the policy file, uninstall the avakill package, run the approve
command, or modify avakill source code.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any

from avakill.core.models import Decision, ToolCall

# Tool name patterns that indicate write/delete/modify intent
_WRITE_TOOL_PATTERNS = [
    "*write*",
    "*delete*",
    "*remove*",
    "*create*",
    "*overwrite*",
    "*modify*",
    "*patch*",
    "*move*",
    "*rename*",
]

# Policy file basenames to protect
_POLICY_FILES = ("avakill.yaml", "avakill.yml")

# Patterns for dangerous commands in argument content
_UNINSTALL_PATTERN = re.compile(
    r"(?:pip3?|python3?\s+-m\s+pip|uv|poetry)\s+"
    r"(?:uninstall|remove)\s+avakill",
    re.IGNORECASE,
)

_APPROVE_PATTERN = re.compile(
    r"avakill\s+approve\b",
    re.IGNORECASE,
)

# Shell commands that delete/overwrite the policy file
# Matches both "rm avakill.yaml" and "avakill.yaml" after "> " or "mv "
_SHELL_POLICY_PATTERN = re.compile(
    r"(?:"
    # rm/del targeting policy file
    r"(?:rm|del|unlink)\s+(?:.*\s)?(?:avakill\.ya?ml)"
    r"|"
    # truncate via redirect
    r">\s*(?:avakill\.ya?ml)"
    r"|"
    # sed -i modifying policy file
    r"sed\s+.*(?:avakill\.ya?ml)"
    r"|"
    # mv policy file away
    r"mv\s+(?:.*\s)?(?:avakill\.ya?ml)"
    r")"
    # Negative lookahead: allow .proposed.yaml
    r"(?!.*\.proposed\.ya?ml)",
    re.IGNORECASE,
)

# Writes to avakill source directories
_SOURCE_WRITE_PATTERN = re.compile(
    r"(?:site-packages|src)/avakill/",
    re.IGNORECASE,
)

_SOURCE_ACTION_PATTERN = re.compile(
    r"(?:write|delete|remove|overwrite|modify|patch|rm|unlink|mv|sed|>"
    r"|create|truncate)",
    re.IGNORECASE,
)


class SelfProtection:
    """Hardcoded self-protection that cannot be overridden by policy.

    Call :meth:`check` before evaluating user-defined rules. Returns a deny
    ``Decision`` if the tool call would weaken avakill's own guardrails,
    or ``None`` to proceed to normal policy evaluation.
    """

    def check(self, tool_call: ToolCall) -> Decision | None:
        """Check a tool call against self-protection rules.

        Returns:
            A deny ``Decision`` if the call is blocked, or ``None`` to proceed.
        """
        # Layer 1: tool name + path check
        reason = self._check_tool_name_and_path(tool_call)
        if reason:
            return self._deny(reason)

        # Layer 2: argument content scanning
        reason = self._scan_arguments(tool_call)
        if reason:
            return self._deny(reason)

        return None

    def _check_tool_name_and_path(self, tool_call: ToolCall) -> str | None:
        """Check if a write/delete tool targets a policy file."""
        tool_lower = tool_call.tool_name.lower()
        is_write_tool = any(
            fnmatch(tool_lower, pat) for pat in _WRITE_TOOL_PATTERNS
        )
        if not is_write_tool:
            return None

        # Check if any argument value references a protected policy file
        for value in tool_call.arguments.values():
            value_str = str(value).lower()
            for policy_file in _POLICY_FILES:
                if policy_file in value_str and ".proposed." not in value_str:
                    return (
                        f"Self-protection: blocked {tool_call.tool_name} targeting "
                        f"policy file '{policy_file}'. Use .proposed.yaml for staging."
                    )
        return None

    def _scan_arguments(self, tool_call: ToolCall) -> str | None:
        """Scan all argument values for dangerous command patterns."""
        scan_text = self._build_scan_text(tool_call)

        # Check for package uninstall
        if _UNINSTALL_PATTERN.search(scan_text):
            return "Self-protection: blocked attempt to uninstall avakill."

        # Check for approve command (only humans should run this)
        if _APPROVE_PATTERN.search(scan_text):
            return (
                "Self-protection: blocked 'avakill approve' — "
                "only humans may activate policies."
            )

        # Check for shell commands targeting policy file
        if _SHELL_POLICY_PATTERN.search(scan_text):
            return (
                "Self-protection: blocked shell command targeting policy file. "
                "Use .proposed.yaml for staging."
            )

        # Check for writes to avakill source
        if _SOURCE_WRITE_PATTERN.search(scan_text) and _SOURCE_ACTION_PATTERN.search(
            scan_text
        ):
            return "Self-protection: blocked modification of avakill source files."

        return None

    @staticmethod
    def _build_scan_text(tool_call: ToolCall) -> str:
        """Concatenate tool name + all argument values into one string."""
        parts: list[str] = [tool_call.tool_name]
        for value in tool_call.arguments.values():
            parts.append(str(value))
        return " ".join(parts)

    @staticmethod
    def _deny(reason: str) -> Decision:
        """Create a deny Decision for self-protection."""
        return Decision(
            allowed=False,
            action="deny",
            policy_name="self-protection",
            reason=reason,
        )
