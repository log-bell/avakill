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
        category: Display grouping (shell, sql, tools, rate-limit, access).
        rule_data: PolicyRule-compatible dict, ready for yaml.dump().
        configurable: Fields the user can customize (e.g. rate_limit.max_calls).
        base: If True, always included in generated policies.
        default_on: If True, pre-selected in interactive menu.
    """

    id: str
    label: str
    description: str
    category: str
    rule_data: dict = field(default_factory=dict)
    configurable: list[str] = field(default_factory=list)
    base: bool = False
    default_on: bool = False


# ---------------------------------------------------------------------------
# Base rules (always included)
# ---------------------------------------------------------------------------

_BASE_RULES: list[RuleDef] = [
    RuleDef(
        id="catastrophic-shell",
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
        id="catastrophic-sql-shell",
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
        id="catastrophic-sql-db",
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
        id="dangerous-shell",
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
        id="destructive-sql",
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
        id="destructive-tools",
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
        id="package-install",
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
        id="web-rate-limit",
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
        id="agent-rate-limit",
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
        id="file-write-approval",
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
        id="shell-allowlist",
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
        id="sensitive-files",
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
# Combined catalog
# ---------------------------------------------------------------------------

ALL_RULES: list[RuleDef] = _BASE_RULES + _OPTIONAL_RULES

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
    return list(_OPTIONAL_RULES)


def get_optional_rule_ids() -> list[str]:
    """Return IDs of all optional rules in catalog order."""
    return [r.id for r in _OPTIONAL_RULES]


def get_default_on_ids() -> set[str]:
    """Return IDs of optional rules that are on by default."""
    return {r.id for r in _OPTIONAL_RULES if r.default_on}


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
    for rule in _OPTIONAL_RULES:
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
