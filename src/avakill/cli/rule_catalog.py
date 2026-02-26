"""Composable rule catalog for AvaKill policy generation.

Defines individual policy rules as RuleDef entries. Users pick from an
interactive menu; selected rules are assembled into a valid PolicyConfig YAML.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

import yaml

# ---------------------------------------------------------------------------
# Shared tool-name constants (canonical + agent-native names)
# ---------------------------------------------------------------------------

_SHELL_TOOLS: list[str] = [
    # Canonical
    "shell_execute",
    # Claude Code
    "Bash",
    # Gemini CLI
    "run_shell_command",
    # Windsurf
    "run_command",
    # OpenAI Codex
    "shell",
    "local_shell",
    "exec_command",
    # Generic globs
    "shell_*",
    "bash_*",
    "command_*",
]

_SQL_TOOLS: list[str] = [
    "database_*",
    "sql_*",
    "execute_sql",
    "run_query",
]

_WRITE_TOOLS: list[str] = [
    # Claude Code
    "Write",
    "Edit",
    "MultiEdit",
    # Gemini CLI
    "write_file",
    "edit_file",
    # Windsurf
    "write_code",
    # OpenAI Codex
    "apply_patch",
    # Generic globs
    "*_write",
    "*_create",
    "*_update",
    "*_edit",
]

_GIT_TOOLS: list[str] = [
    *_SHELL_TOOLS,  # git commands run via shell
]

_DOCKER_TOOLS: list[str] = [
    *_SHELL_TOOLS,  # docker/kubectl commands run via shell
]

_CLOUD_TOOLS: list[str] = [
    *_SHELL_TOOLS,  # aws/gcloud/az commands run via shell
    "cloud_*",
    "aws_*",
    "gcloud_*",
    "azure_*",
]

_NETWORK_TOOLS: list[str] = [
    *_SHELL_TOOLS,  # curl/wget/ssh run via shell
    "http_*",
    "fetch_*",
    "web_*",
]

_READ_TOOLS: list[str] = [
    # Claude Code
    "Read",
    "Glob",
    "Grep",
    "LS",
    "WebFetch",
    # OpenAI Codex
    "grep_files",
    # Generic globs
    "search_*",
    "get_*",
    "list_*",
    "read_*",
    "query_*",
    "fetch_*",
    "find_*",
    "lookup_*",
    "*_search",
    "*_get",
    "*_list",
    "*_read",
    "*_query",
    "*_fetch",
    "*_find",
    "*_lookup",
]


# ---------------------------------------------------------------------------
# RuleDef dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleDef:
    """A single rule definition in the catalog.

    Attributes:
        id: Stable identifier used in --rule flags and config persistence.
        label: Short menu label for display.
        description: One-line human-readable explanation.
        category: Display grouping (shell, sql, tools, rate-limit, access, filesystem).
        rule_data: PolicyRule-compatible dict, ready for yaml.dump().
        configurable: Fields the user can customize (e.g. rate_limit.max_calls).
        base: If True, always included in generated policies.
        default_on: If True, pre-selected in interactive menu.
        tier: Engine capability tier (1=substring, 2=path-resolve, 3=command-parse).
    """

    id: str
    label: str
    description: str
    category: str
    rule_data: dict = field(default_factory=dict)
    configurable: list[str] = field(default_factory=list)
    base: bool = False
    default_on: bool = False
    tier: int = 1


# ---------------------------------------------------------------------------
# Base rules (always included)
# ---------------------------------------------------------------------------

_BASE_RULES: list[RuleDef] = [
    RuleDef(
        id="block-catastrophic-shell",
        label="Catastrophic shell commands",
        description="Block rm -rf /, mkfs, dd if=, > /dev/, fork bombs",
        category="shell",
        rule_data={
            "name": "block-catastrophic-shell",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "rm -rf /",
                        "rm -rf /*",
                        "mkfs",
                        "> /dev/",
                        "dd if=",
                        ":(){ :|:& };:",
                    ],
                },
            },
            "message": "Catastrophic shell command blocked.",
        },
        base=True,
    ),
    RuleDef(
        id="block-catastrophic-sql-shell",
        label="Catastrophic SQL (shell)",
        description="Block DROP DATABASE/SCHEMA via shell tools",
        category="sql",
        rule_data={
            "name": "block-catastrophic-sql-shell",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["DROP DATABASE", "DROP SCHEMA"],
                },
            },
            "message": "Destructive database command blocked.",
        },
        base=True,
    ),
    RuleDef(
        id="block-catastrophic-sql-db",
        label="Catastrophic SQL (database)",
        description="Block DROP DATABASE/SCHEMA via database tools",
        category="sql",
        rule_data={
            "name": "block-catastrophic-sql-db",
            "tools": list(_SQL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "query": ["DROP DATABASE", "DROP SCHEMA"],
                },
            },
            "message": "Destructive database command blocked.",
        },
        base=True,
    ),
]

# ---------------------------------------------------------------------------
# Optional rules (interactive menu)
# ---------------------------------------------------------------------------

_OPTIONAL_RULES: list[RuleDef] = [
    RuleDef(
        id="block-dangerous-shell",
        label="Dangerous shell commands",
        description="Block rm -rf, sudo, chmod 777",
        category="shell",
        rule_data={
            "name": "block-dangerous-shell",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["rm -rf", "sudo", "chmod 777"],
                },
            },
            "message": "Dangerous shell command blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-destructive-sql",
        label="Destructive SQL operations",
        description="Block DELETE, TRUNCATE, ALTER, DROP TABLE",
        category="sql",
        rule_data={
            "name": "block-destructive-sql",
            "tools": list(_SQL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "query": ["DELETE", "TRUNCATE", "ALTER", "DROP TABLE"],
                },
            },
            "message": "Destructive SQL blocked. Use a manual migration.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-destructive-tools",
        label="Destructive tool patterns",
        description="Block delete_*, remove_*, destroy_* tools",
        category="tools",
        rule_data={
            "name": "block-destructive-tools",
            "tools": [
                "delete_*",
                "remove_*",
                "destroy_*",
                "drop_*",
                "*_delete",
                "*_remove",
                "*_destroy",
                "*_drop",
            ],
            "action": "deny",
            "message": "Destructive operations are blocked. Run manually or update your policy.",
        },
        default_on=True,
    ),
    RuleDef(
        id="approve-package-installs",
        label="Package install approval",
        description="Require approval for pip install, npm install -g, brew install",
        category="shell",
        rule_data={
            "name": "approve-package-installs",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": ["pip install", "npm install -g", "brew install"],
                },
            },
            "message": "Package installation requires approval.",
        },
        default_on=False,
    ),
    RuleDef(
        id="rate-limit-web-search",
        label="Web search rate limit",
        description="Rate limit web search calls (default: 30/min)",
        category="rate-limit",
        rule_data={
            "name": "rate-limit-web-search",
            "tools": [
                "web_search",
                "WebSearch",
                "web_fetch",
            ],
            "action": "allow",
            "rate_limit": {
                "max_calls": 30,
                "window": "1m",
            },
        },
        configurable=["rate_limit.max_calls"],
        default_on=False,
    ),
    RuleDef(
        id="rate-limit-agent-spawn",
        label="Agent spawning rate limit",
        description="Rate limit agent/task spawning (default: 20/min)",
        category="rate-limit",
        rule_data={
            "name": "rate-limit-agents",
            "tools": [
                "agent_spawn",
                "Task",
            ],
            "action": "allow",
            "rate_limit": {
                "max_calls": 20,
                "window": "1m",
            },
        },
        configurable=["rate_limit.max_calls"],
        default_on=False,
    ),
    RuleDef(
        id="require-file-write-approval",
        label="File write approval",
        description="Require human approval for all write/edit tools",
        category="access",
        rule_data={
            "name": "approve-file-writes",
            "tools": list(_WRITE_TOOLS),
            "action": "require_approval",
            "message": "Write operations require human approval.",
        },
        default_on=False,
    ),
    RuleDef(
        id="shell-command-allowlist",
        label="Shell command allowlist",
        description="Only allow approved shell commands (echo, ls, git, python, ...)",
        category="shell",
        rule_data={
            "name": "allow-safe-shell-only",
            "tools": list(_SHELL_TOOLS),
            "action": "allow",
            "conditions": {
                "shell_safe": True,
                "command_allowlist": [
                    "echo",
                    "ls",
                    "cat",
                    "pwd",
                    "git",
                    "python",
                    "python3",
                    "pip",
                    "npm",
                    "node",
                    "make",
                    "which",
                    "whoami",
                    "date",
                    "uname",
                    "head",
                    "tail",
                    "wc",
                    "file",
                    "stat",
                ],
            },
            "message": "Safe shell commands allowed (no metacharacters).",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-sensitive-file-access",
        label="Sensitive file access",
        description="Block reads to .env, .ssh/, credentials, API keys",
        category="access",
        rule_data={
            "name": "block-sensitive-file-access",
            "tools": list(_READ_TOOLS) + list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "file_path": [
                        ".env",
                        ".ssh/",
                        ".aws/",
                        ".gnupg/",
                        "credentials.json",
                        "serviceAccountKey.json",
                        "secrets.yaml",
                        "secrets.yml",
                        ".pem",
                        ".key",
                    ],
                },
            },
            "message": "Access to sensitive files is blocked.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# T2 rules — path resolution (tilde, env vars, dotdot, symlinks)
# ---------------------------------------------------------------------------

_T2_RULES: list[RuleDef] = [
    RuleDef(
        id="block-catastrophic-deletion",
        label="Catastrophic deletion (path-aware)",
        description="Block rm -rf targeting any resolved absolute path (resolves ~/,$HOME,../)",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-catastrophic-deletion",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {"command": ["rm -rf", "rm -r"]},
                "path_match": {"command": ["~/", "/"]},
            },
            "message": "Catastrophic recursive deletion blocked (path resolved).",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-deletion-outside-workspace",
        label="Deletion outside workspace",
        description="Block recursive deletion outside project workspace",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-deletion-outside-workspace",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {"command": ["rm -rf", "rm -r"]},
                "path_not_match": {"command": ["__workspace__"]},
            },
            "message": "Recursive deletion outside workspace blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-symlink-escape",
        label="Symlink escape detection",
        description="Catch symlinks resolving to sensitive system dirs",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-symlink-escape",
            "tools": list(_READ_TOOLS) + list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": ["/etc/", "/usr/", "~/.ssh/", "~/.aws/"],
                },
            },
            "message": "Path resolves to a protected system directory (possible symlink escape).",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-ownership-changes",
        label="Ownership changes outside workspace",
        description="Block chown/chgrp targeting paths outside workspace",
        category="shell",
        tier=2,
        rule_data={
            "name": "block-ownership-changes",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {"command": ["chown", "chgrp"]},
                "path_not_match": {"command": ["__workspace__"]},
            },
            "message": "Ownership changes outside workspace blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-system-dir-writes",
        label="System directory writes",
        description="Block file writes to /etc/, /usr/, /sbin/, /boot/, /System/",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-system-dir-writes",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "/etc/",
                        "/usr/",
                        "/sbin/",
                        "/boot/",
                        "/System/",
                        "/Library/",
                    ],
                },
            },
            "message": "Writes to system directories blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-profile-modification",
        label="Shell profile modification",
        description="Require approval for edits to .bashrc, .zshrc, .profile",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-profile-modification",
            "tools": list(_WRITE_TOOLS),
            "action": "require_approval",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "~/.bashrc",
                        "~/.zshrc",
                        "~/.profile",
                        "~/.bash_profile",
                    ],
                },
            },
            "message": "Shell profile modification requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-startup-persistence",
        label="Startup persistence",
        description="Block writes to LaunchAgents, systemd, cron dirs",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-startup-persistence",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "~/Library/LaunchAgents/",
                        "/Library/LaunchDaemons/",
                        "/etc/systemd/",
                        "~/.config/systemd/",
                        "/etc/cron.d/",
                    ],
                },
            },
            "message": "Writes to startup/persistence directories blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="enforce-workspace-boundary",
        label="Workspace boundary",
        description="Block file writes outside the project workspace",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "enforce-workspace-boundary",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_not_match": {"file_path": ["__workspace__"]},
            },
            "message": "File operation outside workspace boundary blocked.",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-ssh-key-access",
        label="SSH key access",
        description="Block read/write access to ~/.ssh/",
        category="access",
        tier=2,
        rule_data={
            "name": "block-ssh-key-access",
            "tools": list(_READ_TOOLS) + list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {"file_path": ["~/.ssh/"]},
            },
            "message": "Access to SSH keys and config blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-cloud-credentials",
        label="Cloud credential access",
        description="Block access to ~/.aws/, ~/.gcloud/, ~/.azure/, ~/.kube/",
        category="access",
        tier=2,
        rule_data={
            "name": "block-cloud-credentials",
            "tools": list(_READ_TOOLS) + list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "~/.aws/",
                        "~/.gcloud/",
                        "~/.azure/",
                        "~/.kube/",
                    ],
                },
            },
            "message": "Access to cloud credentials blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-env-outside-workspace",
        label=".env outside workspace",
        description="Block access to .env files outside the workspace",
        category="access",
        tier=2,
        rule_data={
            "name": "block-env-outside-workspace",
            "tools": list(_READ_TOOLS) + list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {"file_path": [".env"]},
                "path_not_match": {"file_path": ["__workspace__"]},
            },
            "message": "Access to .env files outside workspace blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-launchagent-creation",
        label="LaunchAgent creation (macOS)",
        description="Block plist writes to LaunchAgents/LaunchDaemons",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-launchagent-creation",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "~/Library/LaunchAgents/",
                        "/Library/LaunchDaemons/",
                    ],
                },
            },
            "message": "LaunchAgent/LaunchDaemon creation blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-systemd-persistence",
        label="Systemd persistence (Linux)",
        description="Block writes to systemd unit directories",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-systemd-persistence",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": ["/etc/systemd/", "~/.config/systemd/"],
                },
            },
            "message": "Systemd unit file creation blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-system-file-modification",
        label="System file modification (Linux)",
        description="Block writes to /etc/passwd, /etc/shadow, /etc/sudoers",
        category="filesystem",
        tier=2,
        rule_data={
            "name": "block-system-file-modification",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "/etc/passwd",
                        "/etc/shadow",
                        "/etc/sudoers",
                    ],
                },
            },
            "message": "System file modification blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# T3 rules — compound command splitting (&&, ||, ;, |, subshells)
# ---------------------------------------------------------------------------

_T3_RULES: list[RuleDef] = [
    RuleDef(
        id="detect-command-chaining",
        label="Command chaining detection",
        description="Deny rm -rf, sudo, chmod 777 in compound commands (split by &&/||/;/|)",
        category="shell",
        tier=3,
        rule_data={
            "name": "detect-command-chaining",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["rm -rf", "sudo", "chmod 777", "mkfs", "dd if="],
                },
            },
            "message": "Dangerous command detected in compound expression.",
        },
        default_on=True,
    ),
    RuleDef(
        id="detect-obfuscation",
        label="Obfuscation detection",
        description="Deny base64 -d, xxd -r decode patterns in compound commands",
        category="shell",
        tier=3,
        rule_data={
            "name": "detect-obfuscation",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "base64 -d",
                        "base64 --decode",
                        "xxd -r",
                        "openssl enc -d",
                    ],
                },
            },
            "message": "Obfuscated command execution detected.",
        },
        default_on=True,
    ),
    RuleDef(
        id="detect-pipe-to-shell",
        label="Pipe-to-shell detection",
        description="Deny piping to sh/bash/zsh/python/perl/ruby interpreters",
        category="shell",
        tier=3,
        rule_data={
            "name": "detect-pipe-to-shell",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "| sh",
                        "| bash",
                        "| zsh",
                        "| python",
                        "| python3",
                        "| perl",
                        "| ruby",
                        "| node",
                    ],
                },
            },
            "message": "Piping to shell interpreter detected.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# T4 rules — cross-call correlation (session-level behavioral analysis)
# ---------------------------------------------------------------------------

_T4_RULES: list[RuleDef] = [
    RuleDef(
        id="detect-encode-transmit",
        label="Encode-transmit detection",
        description="Detect read-credential -> encode -> transmit exfiltration chains",
        category="network",
        tier=4,
        rule_data={
            "name": "detect-encode-transmit",
            "tools": ["all"],
            "action": "deny",
            "message": "Cross-call encode-transmit pattern detected.",
        },
        default_on=True,
    ),
    RuleDef(
        id="detect-behavioral-anomaly",
        label="Behavioral anomaly detection",
        description="Detect rapid file deletion bursts and direct credential exfiltration",
        category="agent",
        tier=4,
        rule_data={
            "name": "detect-behavioral-anomaly",
            "tools": ["all"],
            "action": "deny",
            "message": "Cross-call behavioral anomaly detected.",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-clipboard-exfil",
        label="Clipboard exfiltration",
        description="Detect credential read followed by clipboard write (pbcopy/xclip)",
        category="network",
        tier=4,
        rule_data={
            "name": "block-clipboard-exfil",
            "tools": ["all"],
            "action": "deny",
            "message": "Cross-call clipboard exfiltration pattern detected.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# T5 rules — content scanning (secrets, prompt injection)
# ---------------------------------------------------------------------------

_T5_RULES: list[RuleDef] = [
    RuleDef(
        id="detect-secrets-outbound",
        label="Secret detection",
        description="Regex + entropy scan of outbound data for API keys, tokens, private keys",
        category="access",
        tier=5,
        rule_data={
            "name": "detect-secrets-outbound",
            "tools": ["all"],
            "action": "deny",
            "conditions": {
                "content_scan": ["secrets"],
            },
            "message": "Secret or API key detected in tool call arguments.",
        },
        default_on=True,
    ),
    RuleDef(
        id="detect-prompt-injection",
        label="Prompt injection detection",
        description="Detect instruction-override patterns in argument values",
        category="agent",
        tier=5,
        rule_data={
            "name": "detect-prompt-injection",
            "tools": ["all"],
            "action": "deny",
            "conditions": {
                "content_scan": ["prompt_injection"],
            },
            "message": "Prompt injection pattern detected in tool call arguments.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# Filesystem Protection — extra rules
# ---------------------------------------------------------------------------

_FILESYSTEM_EXTRA_RULES: list[RuleDef] = [
    RuleDef(
        id="block-destructive-disk-ops",
        label="Destructive disk operations",
        description="Block dd if=/dev/zero, mkfs, fdisk, diskutil eraseDisk, shred /dev/",
        category="filesystem",
        rule_data={
            "name": "block-destructive-disk-ops",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "dd if=/dev/zero",
                        "mkfs",
                        "fdisk",
                        "diskutil eraseDisk",
                        "diskpart",
                        "shred /dev/",
                    ],
                },
            },
            "message": "Destructive disk operation blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-device-writes",
        label="Device file writes",
        description="Block writes to /dev/sd*, /dev/nvme*, /dev/mem, /dev/kmem",
        category="filesystem",
        rule_data={
            "name": "block-device-writes",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": ["/dev/sd", "/dev/nvme", "/dev/mem", "/dev/kmem"],
                },
            },
            "message": "Writes to device files blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="require-safe-delete",
        label="Safe delete suggestion",
        description="Flag rm/del/Remove-Item and suggest trash alternatives",
        category="filesystem",
        rule_data={
            "name": "require-safe-delete",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": ["rm ", "del ", "Remove-Item"],
                },
            },
            "message": "Consider using trash (trash-cli, gio trash) instead of permanent deletion.",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-fork-bombs",
        label="Fork bomb detection",
        description="Block fork bombs and infinite loop patterns",
        category="filesystem",
        rule_data={
            "name": "block-fork-bombs",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        ":(){ :|:& };:",
                        "while true; do",
                        "fork()",
                    ],
                },
            },
            "message": "Fork bomb or resource exhaustion pattern blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# Shell Safety — extra rules
# ---------------------------------------------------------------------------

_SHELL_EXTRA_RULES: list[RuleDef] = [
    RuleDef(
        id="block-privilege-escalation",
        label="Privilege escalation",
        description="Require approval for sudo, su, doas, runas, pkexec",
        category="shell",
        rule_data={
            "name": "block-privilege-escalation",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": [
                        "sudo ",
                        "su ",
                        "doas ",
                        "runas",
                        "pkexec",
                        "Start-Process -Verb RunAs",
                    ],
                },
            },
            "message": "Privilege escalation requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-permission-changes",
        label="Permission changes",
        description="Block chmod 777, chmod u+s, chmod -R, icacls",
        category="shell",
        rule_data={
            "name": "block-permission-changes",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["chmod 777", "chmod u+s", "chmod -R", "icacls"],
                },
            },
            "message": "Dangerous permission change blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-pipe-to-shell",
        label="Pipe-to-shell (T1 substring)",
        description="Block curl | bash, wget | sh, Invoke-Expression patterns",
        category="shell",
        rule_data={
            "name": "block-pipe-to-shell",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "curl | bash",
                        "curl |bash",
                        "wget | sh",
                        "wget |sh",
                        "Invoke-Expression",
                    ],
                },
            },
            "message": "Pipe-to-shell execution blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-critical-process-kill",
        label="Critical process kill",
        description="Block kill -9, killall, pkill targeting system processes",
        category="shell",
        rule_data={
            "name": "block-critical-process-kill",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["kill -9", "killall", "pkill"],
                },
            },
            "message": "Killing critical processes blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="limit-command-timeout",
        label="Command timeout limit",
        description="Block nohup and long-running background commands",
        category="shell",
        rule_data={
            "name": "limit-command-timeout",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["nohup"],
                },
            },
            "message": "Long-running background command blocked.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# Database Safety — extra rules
# ---------------------------------------------------------------------------

_DB_EXTRA_RULES: list[RuleDef] = [
    RuleDef(
        id="block-unqualified-dml",
        label="Unqualified DML",
        description="Block DELETE FROM and UPDATE SET without WHERE clause",
        category="sql",
        rule_data={
            "name": "block-unqualified-dml",
            "tools": list(_SQL_TOOLS) + list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["DELETE FROM", "UPDATE SET"],
                    "query": ["DELETE FROM", "UPDATE SET"],
                },
            },
            "message": "Unqualified DELETE/UPDATE blocked. Add a WHERE clause.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-db-permission-changes",
        label="Database permission changes",
        description="Block GRANT ALL, REVOKE, ALTER USER, CREATE USER, DROP USER",
        category="sql",
        rule_data={
            "name": "block-db-permission-changes",
            "tools": list(_SQL_TOOLS) + list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["GRANT ALL", "REVOKE", "ALTER USER", "CREATE USER", "DROP USER"],
                    "query": ["GRANT ALL", "REVOKE", "ALTER USER", "CREATE USER", "DROP USER"],
                },
            },
            "message": "Database permission change blocked.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# Version Control — new category
# ---------------------------------------------------------------------------

_VCS_RULES: list[RuleDef] = [
    RuleDef(
        id="block-force-push",
        label="Force push",
        description="Block git push --force, git filter-branch, bfg",
        category="vcs",
        rule_data={
            "name": "block-force-push",
            "tools": list(_GIT_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "git push --force",
                        "git push -f",
                        "git filter-branch",
                        "bfg",
                    ],
                },
            },
            "message": "Force push blocked. Use --force-with-lease or push normally.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-branch-deletion",
        label="Branch deletion",
        description="Block deletion of main/master branches",
        category="vcs",
        rule_data={
            "name": "block-branch-deletion",
            "tools": list(_GIT_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "git branch -D main",
                        "git branch -D master",
                        "git push origin --delete main",
                        "git push origin --delete master",
                    ],
                },
            },
            "message": "Deletion of protected branches blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="detect-credential-commit",
        label="Credential commit detection",
        description="Block git add of .env, *.pem, *.key, id_rsa, credentials.json",
        category="vcs",
        rule_data={
            "name": "detect-credential-commit",
            "tools": list(_GIT_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "git add .env",
                        "git add *.pem",
                        "git add *.key",
                        "git add id_rsa",
                        "git add credentials.json",
                    ],
                },
            },
            "message": "Committing credential files blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# Supply Chain — new category
# ---------------------------------------------------------------------------

_SUPPLY_CHAIN_RULES: list[RuleDef] = [
    RuleDef(
        id="block-registry-manipulation",
        label="Registry manipulation",
        description="Block npm/pip registry URL changes",
        category="supply-chain",
        rule_data={
            "name": "block-registry-manipulation",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "npm config set registry",
                        "pip config set global.index-url",
                    ],
                },
            },
            "message": "Package registry manipulation blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="flag-postinstall-scripts",
        label="Postinstall scripts",
        description="Flag npm install without --ignore-scripts",
        category="supply-chain",
        rule_data={
            "name": "flag-postinstall-scripts",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": ["npm install"],
                },
            },
            "message": "npm install may run postinstall scripts. Consider --ignore-scripts.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# Network & Exfiltration — new category
# ---------------------------------------------------------------------------

_NETWORK_RULES: list[RuleDef] = [
    RuleDef(
        id="restrict-outbound-http",
        label="Outbound HTTP restriction",
        description="Block curl, wget, Invoke-WebRequest",
        category="network",
        rule_data={
            "name": "restrict-outbound-http",
            "tools": list(_NETWORK_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["curl", "wget", "Invoke-WebRequest"],
                },
            },
            "message": "Outbound HTTP request blocked.",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-dns-exfiltration",
        label="DNS exfiltration",
        description="Block dig/nslookup with encoded subdomains",
        category="network",
        rule_data={
            "name": "block-dns-exfiltration",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["dig", "nslookup"],
                },
            },
            "message": "DNS lookup blocked (potential exfiltration).",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-ssh-unknown-hosts",
        label="SSH to unknown hosts",
        description="Require approval for ssh and scp connections",
        category="network",
        rule_data={
            "name": "block-ssh-unknown-hosts",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": ["ssh ", "scp "],
                },
            },
            "message": "SSH/SCP connection requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-port-binding",
        label="Port binding",
        description="Block nc -l, socat, python -m http.server",
        category="network",
        rule_data={
            "name": "block-port-binding",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["nc -l", "socat", "python -m http.server"],
                },
            },
            "message": "Port binding blocked.",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-firewall-changes",
        label="Firewall changes",
        description="Block iptables, ufw, pfctl, netsh advfirewall",
        category="network",
        rule_data={
            "name": "block-firewall-changes",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["iptables", "ufw", "pfctl", "netsh advfirewall"],
                },
            },
            "message": "Firewall modification blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-browser-data-access",
        label="Browser data access",
        description="Block access to Chrome/Firefox/Safari profile directories",
        category="network",
        rule_data={
            "name": "block-browser-data-access",
            "tools": list(_READ_TOOLS) + list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        "Library/Application Support/Google/Chrome/",
                        ".mozilla/firefox/",
                        "Library/Safari/",
                        "AppData/Local/Google/Chrome/",
                        "AppData/Roaming/Mozilla/Firefox/",
                    ],
                },
            },
            "message": "Access to browser profile data blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# Secrets & Credentials — extra rules
# ---------------------------------------------------------------------------

_SECRETS_EXTRA_RULES: list[RuleDef] = [
    RuleDef(
        id="block-credential-stores",
        label="Credential store access",
        description="Block access to macOS Keychain, gnupg, Windows Credential Manager",
        category="access",
        rule_data={
            "name": "block-credential-stores",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "security dump-keychain",
                        "cmdkey",
                        "vaultcmd",
                    ],
                },
            },
            "message": "Credential store access blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-path-poisoning",
        label="PATH poisoning",
        description="Block untrusted PATH prepends like /tmp: or .:",
        category="access",
        rule_data={
            "name": "block-path-poisoning",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "export PATH=/tmp:",
                        "export PATH=.:",
                    ],
                },
            },
            "message": "PATH poisoning blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-env-secret-exposure",
        label="Environment secret exposure",
        description="Block printenv/env/set piped to other commands",
        category="access",
        rule_data={
            "name": "block-env-secret-exposure",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["printenv |", "env |", "set |"],
                },
            },
            "message": "Environment variable exposure blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# Cloud & Infrastructure — new category
# ---------------------------------------------------------------------------

_CLOUD_RULES: list[RuleDef] = [
    RuleDef(
        id="block-cloud-resource-deletion",
        label="Cloud resource deletion",
        description="Require approval for aws s3 rm, ec2 terminate, terraform destroy",
        category="cloud",
        rule_data={
            "name": "block-cloud-resource-deletion",
            "tools": list(_CLOUD_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": [
                        "aws s3 rm",
                        "aws s3 rb",
                        "aws ec2 terminate-instances",
                        "gcloud compute instances delete",
                        "terraform destroy",
                    ],
                },
            },
            "message": "Cloud resource deletion requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-iam-changes",
        label="IAM changes",
        description="Block aws iam, gcloud iam, az role modifications",
        category="cloud",
        rule_data={
            "name": "block-iam-changes",
            "tools": list(_CLOUD_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["aws iam", "gcloud iam", "az role"],
                },
            },
            "message": "IAM modification blocked.",
        },
        default_on=False,
    ),
    RuleDef(
        id="block-backup-deletion",
        label="Backup deletion",
        description="Block deletion of cloud snapshots and backups",
        category="cloud",
        rule_data={
            "name": "block-backup-deletion",
            "tools": list(_CLOUD_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "aws rds delete-db-snapshot",
                        "aws ec2 delete-snapshot",
                    ],
                },
            },
            "message": "Backup/snapshot deletion blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-destructive-docker",
        label="Destructive Docker operations",
        description="Require approval for docker system prune, docker volume rm",
        category="cloud",
        rule_data={
            "name": "block-destructive-docker",
            "tools": list(_DOCKER_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": ["docker system prune", "docker volume rm"],
                },
            },
            "message": "Destructive Docker operation requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-container-escape",
        label="Container escape",
        description="Block docker run --privileged, -v /:/host, nsenter --target 1",
        category="cloud",
        rule_data={
            "name": "block-container-escape",
            "tools": list(_DOCKER_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "docker run --privileged",
                        "-v /:/host",
                        "nsenter --target 1",
                    ],
                },
            },
            "message": "Container escape attempt blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-k8s-destruction",
        label="Kubernetes destruction",
        description="Block kubectl delete namespace/deployment/pvc, helm uninstall",
        category="cloud",
        rule_data={
            "name": "block-k8s-destruction",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "kubectl delete namespace",
                        "kubectl delete deployment",
                        "kubectl delete pvc",
                        "helm uninstall",
                    ],
                },
            },
            "message": "Kubernetes resource destruction blocked.",
        },
        default_on=False,
    ),
]

# ---------------------------------------------------------------------------
# AI Agent Safety — new category
# ---------------------------------------------------------------------------

_AGENT_RULES: list[RuleDef] = [
    RuleDef(
        id="detect-mcp-tool-poisoning",
        label="MCP tool poisoning",
        description="Detect invisible Unicode and instruction patterns in tool descriptions",
        category="agent",
        rule_data={
            "name": "detect-mcp-tool-poisoning",
            "tools": ["all"],
            "action": "deny",
            "conditions": {
                "content_scan": ["mcp_poisoning"],
            },
            "message": "MCP tool poisoning pattern detected.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-agent-self-modification",
        label="Agent self-modification",
        description="Block agent config modifications (.claude/, .cursor/, avakill.yaml)",
        category="agent",
        rule_data={
            "name": "block-agent-self-modification",
            "tools": list(_WRITE_TOOLS),
            "action": "deny",
            "conditions": {
                "path_match": {
                    "file_path": [
                        ".claude/settings.json",
                        ".cursor/mcp.json",
                        ".gemini/settings.json",
                        "avakill.yaml",
                    ],
                },
            },
            "message": "Agent self-modification blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="rate-limit-tool-calls",
        label="Tool call rate limit",
        description="Rate limit all tool calls (default: 500/60min)",
        category="agent",
        rule_data={
            "name": "rate-limit-tool-calls",
            "tools": ["all"],
            "action": "allow",
            "rate_limit": {
                "max_calls": 500,
                "window": "60m",
            },
        },
        configurable=["rate_limit.max_calls"],
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# OS Hardening — macOS
# ---------------------------------------------------------------------------

_OS_MACOS_RULES: list[RuleDef] = [
    RuleDef(
        id="block-sip-changes",
        label="SIP changes (macOS)",
        description="Block csrutil disable, csrutil authenticated-root disable",
        category="os",
        rule_data={
            "name": "block-sip-changes",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "csrutil disable",
                        "csrutil authenticated-root disable",
                    ],
                },
            },
            "message": "System Integrity Protection modification blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-tcc-manipulation",
        label="TCC manipulation (macOS)",
        description="Block tccutil reset, TCC.db direct access",
        category="os",
        rule_data={
            "name": "block-tcc-manipulation",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["tccutil reset", "TCC.db"],
                },
            },
            "message": "TCC database manipulation blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-gatekeeper-bypass",
        label="Gatekeeper bypass (macOS)",
        description="Require approval for xattr quarantine removal, spctl disable",
        category="os",
        rule_data={
            "name": "block-gatekeeper-bypass",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": [
                        "xattr -d com.apple.quarantine",
                        "spctl --master-disable",
                    ],
                },
            },
            "message": "Gatekeeper bypass requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-osascript-abuse",
        label="osascript abuse (macOS)",
        description="Require approval for osascript -e, do shell script",
        category="os",
        rule_data={
            "name": "block-osascript-abuse",
            "tools": list(_SHELL_TOOLS),
            "action": "require_approval",
            "conditions": {
                "args_match": {
                    "command": ["osascript -e", "do shell script"],
                },
            },
            "message": "osascript execution requires approval.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-defaults-security",
        label="Security defaults (macOS)",
        description="Block defaults write targeting security domains",
        category="os",
        rule_data={
            "name": "block-defaults-security",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["defaults write"],
                },
            },
            "message": "Modification of macOS security defaults blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# OS Hardening — Linux
# ---------------------------------------------------------------------------

_OS_LINUX_RULES: list[RuleDef] = [
    RuleDef(
        id="block-library-injection",
        label="Library injection (Linux)",
        description="Block LD_PRELOAD, /etc/ld.so.preload, LD_LIBRARY_PATH manipulation",
        category="os",
        rule_data={
            "name": "block-library-injection",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "LD_PRELOAD=",
                        "/etc/ld.so.preload",
                        "LD_LIBRARY_PATH",
                    ],
                },
            },
            "message": "Library injection blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-mac-disablement",
        label="MAC disablement (Linux)",
        description="Block setenforce 0, aa-complain, aa-disable",
        category="os",
        rule_data={
            "name": "block-mac-disablement",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["setenforce 0", "aa-complain", "aa-disable"],
                },
            },
            "message": "Mandatory access control disablement blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-kernel-modification",
        label="Kernel modification (Linux)",
        description="Block sysctl -w, modprobe, insmod",
        category="os",
        rule_data={
            "name": "block-kernel-modification",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": ["sysctl -w", "modprobe", "insmod"],
                },
            },
            "message": "Kernel modification blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# OS Hardening — Windows
# ---------------------------------------------------------------------------

_OS_WINDOWS_RULES: list[RuleDef] = [
    RuleDef(
        id="block-defender-manipulation",
        label="Defender manipulation (Windows)",
        description="Block Set-MpPreference disabling, sc stop WinDefend",
        category="os",
        rule_data={
            "name": "block-defender-manipulation",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "Set-MpPreference -DisableRealtimeMonitoring",
                        "sc stop WinDefend",
                    ],
                },
            },
            "message": "Windows Defender manipulation blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-shadow-copy-deletion",
        label="Shadow copy deletion (Windows)",
        description="Block vssadmin delete shadows, wmic shadowcopy delete",
        category="os",
        rule_data={
            "name": "block-shadow-copy-deletion",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "vssadmin delete shadows",
                        "wmic shadowcopy delete",
                    ],
                },
            },
            "message": "Shadow copy deletion blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-boot-config-changes",
        label="Boot config changes (Windows)",
        description="Block bcdedit modifying recovery and test signing",
        category="os",
        rule_data={
            "name": "block-boot-config-changes",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "bcdedit /set recoveryenabled",
                        "bcdedit /set testsigning",
                    ],
                },
            },
            "message": "Boot configuration change blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-uac-bypass",
        label="UAC bypass (Windows)",
        description="Block fodhelper.exe, eventvwr.exe, DelegateExecute techniques",
        category="os",
        rule_data={
            "name": "block-uac-bypass",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "fodhelper.exe",
                        "eventvwr.exe",
                        "DelegateExecute",
                    ],
                },
            },
            "message": "UAC bypass technique blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-powershell-cradles",
        label="PowerShell cradles (Windows)",
        description="Block IEX, powershell -e, powershell -EncodedCommand",
        category="os",
        rule_data={
            "name": "block-powershell-cradles",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "IEX",
                        "powershell -e",
                        "powershell -EncodedCommand",
                    ],
                },
            },
            "message": "PowerShell download cradle blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-event-log-clearing",
        label="Event log clearing (Windows)",
        description="Block wevtutil cl, Clear-EventLog, ConsoleHost_history.txt deletion",
        category="os",
        rule_data={
            "name": "block-event-log-clearing",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "wevtutil cl",
                        "Clear-EventLog",
                        "ConsoleHost_history.txt",
                    ],
                },
            },
            "message": "Event log clearing blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-lsass-sam-access",
        label="LSASS/SAM access (Windows)",
        description="Block procdump -ma lsass, mimikatz, reg save HKLM\\SAM",
        category="os",
        rule_data={
            "name": "block-lsass-sam-access",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "procdump -ma lsass",
                        "mimikatz",
                        "reg save HKLM\\SAM",
                    ],
                },
            },
            "message": "LSASS/SAM credential access blocked.",
        },
        default_on=True,
    ),
    RuleDef(
        id="block-hidden-accounts",
        label="Hidden accounts (Windows)",
        description="Block net user /add, net localgroup administrators /add",
        category="os",
        rule_data={
            "name": "block-hidden-accounts",
            "tools": list(_SHELL_TOOLS),
            "action": "deny",
            "conditions": {
                "args_match": {
                    "command": [
                        "net user /add",
                        "net localgroup administrators /add",
                    ],
                },
            },
            "message": "Hidden account creation blocked.",
        },
        default_on=True,
    ),
]

# ---------------------------------------------------------------------------
# Combined catalog
# ---------------------------------------------------------------------------

_ALL_OPTIONAL: list[RuleDef] = (
    _OPTIONAL_RULES
    + _T2_RULES
    + _T3_RULES
    + _T4_RULES
    + _T5_RULES
    + _FILESYSTEM_EXTRA_RULES
    + _SHELL_EXTRA_RULES
    + _DB_EXTRA_RULES
    + _VCS_RULES
    + _SUPPLY_CHAIN_RULES
    + _NETWORK_RULES
    + _SECRETS_EXTRA_RULES
    + _CLOUD_RULES
    + _AGENT_RULES
    + _OS_MACOS_RULES
    + _OS_LINUX_RULES
    + _OS_WINDOWS_RULES
)

ALL_RULES: list[RuleDef] = _BASE_RULES + _ALL_OPTIONAL

_RULES_BY_ID: dict[str, RuleDef] = {r.id: r for r in ALL_RULES}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_rule_by_id(rule_id: str) -> RuleDef | None:
    """Return a RuleDef by its stable ID, or None if not found."""
    return _RULES_BY_ID.get(rule_id)


def get_base_rules() -> list[RuleDef]:
    """Return all base rules (always included)."""
    return list(_BASE_RULES)


def get_optional_rules() -> list[RuleDef]:
    """Return all optional rules (user-selectable)."""
    return list(_ALL_OPTIONAL)


def get_optional_rule_ids() -> list[str]:
    """Return IDs of all optional rules in catalog order."""
    return [r.id for r in _ALL_OPTIONAL]


def get_default_on_ids() -> set[str]:
    """Return IDs of optional rules that are on by default."""
    return {r.id for r in _ALL_OPTIONAL if r.default_on}


def build_policy_dict(
    selected_ids: list[str] | set[str],
    default_action: str = "allow",
    extra_rules: list[dict] | None = None,
) -> dict:
    """Assemble a full PolicyConfig dict from selected rule IDs.

    Base rules always come first, then selected optional rules in catalog
    order, then extra rules (e.g. from file scanning), then a trailing
    log-all rule when default_action is "allow".

    Args:
        selected_ids: IDs of optional rules to include.
        default_action: "allow" or "deny".
        extra_rules: Additional rule dicts to append (e.g. from scanner).

    Returns:
        A dict ready for PolicyConfig.model_validate() and yaml.dump().
    """
    selected_set = set(selected_ids)
    policies: list[dict] = []

    # Base rules (always included)
    for rule in _BASE_RULES:
        policies.append(copy.deepcopy(rule.rule_data))

    # Selected optional rules in catalog order
    for rule in _ALL_OPTIONAL:
        if rule.id in selected_set:
            policies.append(copy.deepcopy(rule.rule_data))

    # Extra rules (e.g. from sensitive file scanning)
    if extra_rules:
        for extra in extra_rules:
            policies.append(copy.deepcopy(extra))

    # Trailing log-all when default_action is "allow"
    if default_action == "allow":
        policies.append(
            {
                "name": "log-all",
                "tools": ["all"],
                "action": "allow",
            }
        )

    return {
        "version": "1.0",
        "default_action": default_action,
        "policies": policies,
    }


def get_optional_rules_by_category() -> dict[str, list[RuleDef]]:
    """Return optional rules grouped by category in display order.

    Returns:
        OrderedDict mapping category key to list of RuleDef instances.
        Keys are ordered per CATEGORY_DISPLAY.
    """
    all_optional = get_optional_rules()
    grouped: dict[str, list[RuleDef]] = {key: [] for key in CATEGORY_DISPLAY}
    for rule in all_optional:
        if rule.category in grouped:
            grouped[rule.category].append(rule)
    return grouped


CATEGORY_DISPLAY: dict[str, tuple[str, str]] = {
    "shell": ("Shell Safety", "Dangerous commands, privilege escalation, obfuscation"),
    "sql": ("Database Safety", "Destructive SQL operations"),
    "filesystem": ("Filesystem Protection", "Path-aware deletion, system dirs, persistence"),
    "tools": ("Tool Safety", "Destructive tool name patterns"),
    "access": ("Secrets & Access", "Credentials, sensitive files, content scanning"),
    "rate-limit": ("Rate Limits", "Throttle agent activity"),
    "vcs": ("Version Control", "Force pushes, branch deletion, credential commits"),
    "supply-chain": ("Supply Chain", "Registry manipulation, postinstall scripts"),
    "network": ("Network & Exfiltration", "Outbound HTTP, DNS, SSH, ports, firewalls"),
    "cloud": ("Cloud & Infrastructure", "Cloud resources, IAM, Docker, Kubernetes"),
    "agent": ("AI Agent Safety", "MCP poisoning, self-modification, tool rate limits"),
    "os": ("OS Hardening", "Platform-specific security (macOS, Linux, Windows)"),
}


def generate_yaml(
    selected_ids: list[str] | set[str],
    default_action: str = "allow",
    extra_rules: list[dict] | None = None,
) -> str:
    """Generate a complete policy YAML string.

    Calls build_policy_dict(), validates via PolicyConfig, and dumps as YAML
    with a descriptive header comment.

    Args:
        selected_ids: IDs of optional rules to include.
        default_action: "allow" or "deny".
        extra_rules: Additional rule dicts to append.

    Returns:
        A YAML string ready to write to a file.
    """
    from avakill.core.models import PolicyConfig

    policy_dict = build_policy_dict(selected_ids, default_action, extra_rules)

    # Validate
    PolicyConfig.model_validate(policy_dict)

    # Build header comment
    selected_list = sorted(selected_ids) if isinstance(selected_ids, set) else list(selected_ids)
    base_ids = [r.id for r in _BASE_RULES]

    lines = [
        "# AvaKill Policy",
        "# Generated by avakill setup",
        "#",
        f"# Base rules: {', '.join(base_ids)}",
    ]
    if selected_list:
        lines.append(f"# Selected rules: {', '.join(selected_list)}")
    lines.append("")

    header = "\n".join(lines)
    body = yaml.dump(policy_dict, default_flow_style=False, sort_keys=False)

    return header + body
