"""macOS sandbox-exec SBPL profile generator.

Translates AvaKill deny rules into Apple Sandbox Profile Language (SBPL)
profiles that can be used with sandbox-exec on macOS.

Note: sandbox-exec is deprecated by Apple but still functional.
The generated profiles are useful for defense-in-depth.
"""

from __future__ import annotations

import sys
from pathlib import Path

from avakill.core.models import PolicyConfig, SandboxConfig

# Map canonical tool names to SBPL operations to deny
TOOL_TO_SBPL_OPS: dict[str, list[str]] = {
    "file_write": [
        "file-write*",
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

# SBPL operation categories for grouping
_FILE_WRITE_OPS = {"file-write*", "file-write-data", "file-write-create", "file-write-unlink"}
_PROCESS_OPS = {"process-exec"}
_NETWORK_OPS = {"network-outbound"}

# Known shell paths to deny when shell_execute is blocked
_KNOWN_SHELL_PATHS = [
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/csh",
    "/bin/tcsh",
    "/bin/ksh",
    "/bin/dash",
    "/usr/bin/env",
]

# System paths that should always be writable (sandbox internals, temp)
_SYSTEM_WRITE_PATHS = [
    "/private/var/folders",
    "/dev/null",
    "/dev/dtracehelper",
]


class SandboxProfileError(Exception):
    """Raised when the generated profile would be unusable."""


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

        Uses the ``sandbox`` section of the policy to scope deny rules
        with path exceptions. Never produces global ``(deny process-exec)``
        — that would brick the wrapped command.

        Args:
            config: The policy configuration to translate.

        Returns:
            An SBPL profile string suitable for sandbox-exec -f.

        Raises:
            SandboxProfileError: If the profile would globally deny
                process-exec without path scoping.
        """
        lines: list[str] = [
            "(version 1)",
            "",
            ";; AvaKill-generated sandbox profile",
            ";; Allow everything by default, then deny specific operations",
            "(allow default)",
            "",
        ]

        # Collect denied operations grouped by category
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

        # Safety check: refuse to generate global process-exec denial
        has_process_deny = denied_ops & _PROCESS_OPS
        sandbox_cfg = config.sandbox or SandboxConfig()

        if has_process_deny and not sandbox_cfg.allow_paths.execute:
            raise SandboxProfileError(
                "Policy would globally deny process-exec with no execute "
                "allowlist in sandbox.allow_paths.execute. This would prevent "
                "the wrapped command from starting. Add allowed executable "
                "paths to the sandbox section of your policy."
            )

        # Generate scoped deny rules per category
        file_write_ops = [(op, name) for op, name in deny_sources if op in _FILE_WRITE_OPS]
        process_ops = [(op, name) for op, name in deny_sources if op in _PROCESS_OPS]
        network_ops = [(op, name) for op, name in deny_sources if op in _NETWORK_OPS]

        if file_write_ops:
            lines.extend(self._generate_file_write_rules(file_write_ops, sandbox_cfg))

        if process_ops:
            lines.extend(self._generate_process_rules(process_ops, sandbox_cfg))

        if network_ops:
            lines.extend(self._generate_network_rules(network_ops, sandbox_cfg))

        return "\n".join(lines) + "\n"

    def _generate_file_write_rules(
        self,
        ops: list[tuple[str, str]],
        sandbox_cfg: SandboxConfig,
    ) -> list[str]:
        """Generate scoped file-write deny rules with path exceptions."""
        lines: list[str] = []
        rule_names = sorted({name for _, name in ops})
        op_names = sorted({op for op, _ in ops})

        lines.append(f";; From rules: {', '.join(rule_names)}")

        # Collect allowed write paths
        allowed = list(sandbox_cfg.allow_paths.write) + _SYSTEM_WRITE_PATHS

        for op in op_names:
            if allowed:
                lines.append(f"(deny {op}")
                lines.append("  (require-not")
                for path in allowed:
                    expanded = str(Path(path).expanduser())
                    lines.append(f'    (subpath "{expanded}")')
                lines.append("  ))")
            else:
                # No write allowlist — deny globally (file writes, not exec)
                lines.append(f"(deny {op})")
            lines.append("")

        return lines

    def _generate_process_rules(
        self,
        ops: list[tuple[str, str]],
        sandbox_cfg: SandboxConfig,
    ) -> list[str]:
        """Generate scoped process-exec deny rules.

        Instead of globally denying process-exec (which bricks the command),
        deny specific shell paths and allow the configured executables.
        """
        lines: list[str] = []
        rule_names = sorted({name for _, name in ops})

        lines.append(f";; From rules: {', '.join(rule_names)}")
        lines.append(";; Block known shell interpreters (scoped, not global)")
        lines.append("(deny process-exec")

        # Deny known shells
        for shell_path in _KNOWN_SHELL_PATHS:
            lines.append(f'  (literal "{shell_path}")')

        lines.append(")")
        lines.append("")

        return lines

    def _generate_network_rules(
        self,
        ops: list[tuple[str, str]],
        sandbox_cfg: SandboxConfig,
    ) -> list[str]:
        """Generate scoped network-outbound deny rules with host exceptions."""
        lines: list[str] = []
        rule_names = sorted({name for _, name in ops})

        lines.append(f";; From rules: {', '.join(rule_names)}")

        allowed_hosts = sandbox_cfg.allow_network.connect

        if allowed_hosts:
            lines.append("(deny network-outbound")
            lines.append("  (require-not")
            for host_port in allowed_hosts:
                lines.append(f'    (remote tcp "{host_port}")')
            # Always allow localhost
            lines.append('    (remote tcp "localhost:*")')
            lines.append("  ))")
        else:
            # No allowlist — deny all outbound except localhost
            lines.append("(deny network-outbound")
            lines.append("  (require-not")
            lines.append('    (remote tcp "localhost:*")')
            lines.append("  ))")
        lines.append("")

        return lines

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
