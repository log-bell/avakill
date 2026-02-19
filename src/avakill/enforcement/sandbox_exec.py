"""macOS sandbox-exec SBPL profile generator.

Translates AvaKill deny rules into Apple Sandbox Profile Language (SBPL)
profiles that can be used with sandbox-exec on macOS.

Note: sandbox-exec is deprecated by Apple but still functional.
The generated profiles are useful for defense-in-depth.
"""

from __future__ import annotations

import sys
from pathlib import Path

from avakill.core.models import PolicyConfig

# Map canonical tool names to SBPL operations to deny
TOOL_TO_SBPL_OPS: dict[str, list[str]] = {
    "file_write": [
        "file-write-data",
        "file-write-create",
        "file-write-unlink",
    ],
    "file_delete": [
        "file-write-unlink",
    ],
    "file_edit": [
        "file-write-data",
    ],
    "shell_execute": [
        "process-exec",
    ],
    "web_fetch": [
        "network-outbound",
    ],
    "web_search": [
        "network-outbound",
    ],
}


class SandboxExecEnforcer:
    """macOS sandbox-exec SBPL profile generator.

    Generates Sandbox Profile Language (SBPL) profiles from AvaKill
    policy configurations. The profiles can be used with macOS
    sandbox-exec to enforce restrictions at the OS level.
    """

    @staticmethod
    def available() -> bool:
        """Check if sandbox-exec is available (macOS only).

        Returns:
            True if running on macOS (Darwin).
        """
        return sys.platform == "darwin"

    def generate_profile(self, config: PolicyConfig) -> str:
        """Generate an SBPL profile string from policy deny rules.

        Args:
            config: The policy configuration to translate.

        Returns:
            An SBPL profile string suitable for sandbox-exec -f.
        """
        lines: list[str] = [
            "(version 1)",
            "",
            ";; AvaKill-generated sandbox profile",
            ";; Allow everything by default, then deny specific operations",
            "(allow default)",
            "",
        ]

        denied_ops: set[str] = set()
        deny_sources: list[tuple[str, str]] = []  # (op, rule_name)

        for rule in config.policies:
            if rule.action != "deny":
                continue
            for tool_pattern in rule.tools:
                ops = self._tool_pattern_to_ops(tool_pattern)
                for op in ops:
                    if op not in denied_ops:
                        denied_ops.add(op)
                        deny_sources.append((op, rule.name))

        if not denied_ops:
            lines.append(";; No deny rules found — no additional restrictions")
            return "\n".join(lines) + "\n"

        for op, rule_name in deny_sources:
            lines.append(f";; From rule: {rule_name}")
            lines.append(f"(deny {op})")
            lines.append("")

        return "\n".join(lines) + "\n"

    def write_profile(self, config: PolicyConfig, output: Path) -> Path:
        """Generate and write an SBPL profile to a file.

        Args:
            config: The policy configuration to translate.
            output: Path where the profile should be written.

        Returns:
            The path where the profile was written.
        """
        profile = self.generate_profile(config)
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(profile, encoding="utf-8")
        return output

    def _tool_pattern_to_ops(self, tool_pattern: str) -> list[str]:
        """Convert a tool name pattern to SBPL operations."""
        # Exact match
        if tool_pattern in TOOL_TO_SBPL_OPS:
            return TOOL_TO_SBPL_OPS[tool_pattern]

        # Wildcard — deny all mapped operations
        if tool_pattern in ("*", "all"):
            ops: list[str] = []
            seen: set[str] = set()
            for tool_ops in TOOL_TO_SBPL_OPS.values():
                for op in tool_ops:
                    if op not in seen:
                        seen.add(op)
                        ops.append(op)
            return ops

        # Glob patterns
        from fnmatch import fnmatch

        ops = []
        seen_glob: set[str] = set()
        for tool_name, tool_ops in TOOL_TO_SBPL_OPS.items():
            if fnmatch(tool_name, tool_pattern):
                for op in tool_ops:
                    if op not in seen_glob:
                        seen_glob.add(op)
                        ops.append(op)
        return ops
