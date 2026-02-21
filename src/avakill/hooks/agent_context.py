"""Inject AvaKill context into AI agent instruction files.

Writes a concise avakill reference into each detected agent's context
file (CLAUDE.md, .cursorrules, .windsurfrules, etc.) so the agent knows
how to help users write and modify policies.
"""

from __future__ import annotations

from pathlib import Path

_START_MARKER = "<!-- AVAKILL-CONTEXT-START -->"
_END_MARKER = "<!-- AVAKILL-CONTEXT-END -->"

# Agent name -> context file path relative to project root.
AGENT_CONTEXT_FILES: dict[str, str] = {
    "claude-code": "CLAUDE.md",
    "cursor": ".cursorrules",
    "windsurf": ".windsurfrules",
    "gemini-cli": "GEMINI.md",
    "openclaw": "BOOTSTRAP.md",
}


def _generate_context(policy_path: str = "avakill.yaml") -> str:
    """Generate the avakill context snippet for AI agents."""
    return f"""{_START_MARKER}
## AvaKill — AI Agent Safety Firewall

This project uses [AvaKill](https://github.com/log-bell/avakill)
to enforce safety policies on AI agent tool calls.
The policy file is `{policy_path}`.

### Policy format

Policies are YAML. Rules are evaluated top-to-bottom — **first match wins**.

```yaml
version: "1.0"
default_action: deny  # or allow

policies:
  - name: rule-name
    tools: ["glob_pattern*", "exact_name"]  # fnmatch patterns
    action: allow | deny | require_approval
    conditions:                              # optional
      args_match:
        arg_name: ["substring1", "substring2"]  # case-insensitive
      shell_safe: true                       # reject metacharacters
      command_allowlist: [echo, ls, git]     # first token must be in list
    rate_limit:                              # optional
      max_calls: 10
      window: "60s"                          # 10s, 5m, 1h
    message: "Human-readable denial reason"
```

### Common patterns

- **Block destructive ops**: `tools: ["delete_*", "drop_*"]` with `action: deny`
- **Allow reads**: `tools: ["search_*", "get_*", "read_*", "list_*"]` with `action: allow`
- **Block dangerous shell**: `tools: ["shell_*"]` + \
`args_match: {{command: ["rm -rf", "sudo"]}}` with `action: deny`
- **Safe shell allowlist**: `tools: ["shell_*"]` + `shell_safe: true` + \
`command_allowlist: [echo, ls, git, python]`
- **Rate limit**: `rate_limit: {{max_calls: 10, window: "60s"}}`

### Commands

- `avakill validate {policy_path}` — check policy syntax
- `avakill dashboard` — real-time monitoring
- `avakill schema --format=prompt` — generate a full policy-writing prompt
- `avakill guide policy` — interactive policy creation wizard

### Rules

- Do NOT modify or delete `{policy_path}` unless the user explicitly asks
- When writing policies, put specific deny rules BEFORE general allow rules
- Always validate after changes: `avakill validate {policy_path}`
{_END_MARKER}"""


def inject_context(
    project_dir: Path,
    agents: list[str] | None = None,
    policy_path: str = "avakill.yaml",
) -> list[Path]:
    """Inject avakill context into detected agents' context files.

    Args:
        project_dir: The project root directory.
        agents: List of agent names to inject into. If None, uses all
            agents that have a known context file.
        policy_path: Path to the policy file (for reference in the context).

    Returns:
        List of paths that were created or updated.
    """
    if agents is None:
        from avakill.hooks.installer import detect_agents

        agents = detect_agents()

    context = _generate_context(policy_path)
    updated: list[Path] = []

    for agent in agents:
        filename = AGENT_CONTEXT_FILES.get(agent)
        if filename is None:
            continue

        filepath = project_dir / filename
        _write_context(filepath, context)
        updated.append(filepath)

    return updated


def _write_context(filepath: Path, context: str) -> None:
    """Create or update a context file with the avakill section.

    If the file exists and already has an avakill section (between
    markers), replace it. Otherwise append.
    """
    if filepath.exists():
        existing = filepath.read_text(encoding="utf-8")

        # Replace existing section
        start_idx = existing.find(_START_MARKER)
        end_idx = existing.find(_END_MARKER)
        if start_idx != -1 and end_idx != -1:
            end_idx += len(_END_MARKER)
            updated = existing[:start_idx] + context + existing[end_idx:]
            filepath.write_text(updated, encoding="utf-8")
            return

        # Append to existing file
        if existing and not existing.endswith("\n\n"):
            separator = "\n\n"
        elif existing and not existing.endswith("\n"):
            separator = "\n"
        else:
            separator = ""
        filepath.write_text(existing + separator + context + "\n", encoding="utf-8")
    else:
        filepath.write_text(context + "\n", encoding="utf-8")
