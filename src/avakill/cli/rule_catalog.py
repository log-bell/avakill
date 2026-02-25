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
# Combined catalog
# ---------------------------------------------------------------------------

ALL_RULES: list[RuleDef] = _BASE_RULES + _OPTIONAL_RULES + _T2_RULES + _T3_RULES

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
    """Return all optional rules (user-selectable), including T2 and T3."""
    return list(_OPTIONAL_RULES) + list(_T2_RULES) + list(_T3_RULES)


def get_optional_rule_ids() -> list[str]:
    """Return IDs of all optional rules in catalog order."""
    return [r.id for r in _OPTIONAL_RULES] + [r.id for r in _T2_RULES] + [r.id for r in _T3_RULES]


def get_default_on_ids() -> set[str]:
    """Return IDs of optional rules that are on by default."""
    return {r.id for r in (_OPTIONAL_RULES + _T2_RULES + _T3_RULES) if r.default_on}


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

    # Selected optional rules in catalog order (T1 + T2 + T3)
    for rule in _OPTIONAL_RULES + _T2_RULES + _T3_RULES:
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
