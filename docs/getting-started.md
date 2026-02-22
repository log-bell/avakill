# Getting Started

AvaKill is a safety firewall for AI agents. You define policies in YAML; AvaKill intercepts tool calls and kills anything outside those boundaries.

This guide gets you from zero to a working policy in under 5 minutes.

## Installation

### Recommended: pipx (isolated install)

```bash
pipx install avakill
```

### Or use a virtualenv

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install avakill
```

### With pip directly

```bash
pip install avakill
```

### With framework extras

```bash
pip install "avakill[openai]"       # OpenAI function calling
pip install "avakill[anthropic]"    # Anthropic tool use
pip install "avakill[langchain]"    # LangChain / LangGraph
pip install "avakill[mcp]"          # MCP proxy
pip install "avakill[metrics]"      # Prometheus metrics
pip install "avakill[watch]"        # File-watching (policy hot-reload)
pip install "avakill[all]"          # Everything
```

> **macOS note:** macOS 14+ ships Python 3.12+ which blocks `pip install` at the system level (PEP 668). Use `pipx` or a virtualenv.

> **Note:** Quotes around `"avakill[...]"` are required on zsh (the default macOS shell). Bash works with or without them.

### From source

```bash
git clone https://github.com/log-bell/avakill.git
cd avakill
pip install -e ".[dev]"
```

## 1. Set Up Your Policy

### Interactive setup with `avakill guide`

The recommended way to get started is the interactive TUI:

```bash
avakill guide
```

This opens a 7-section menu covering setup, policies, hooks, signing, monitoring, compliance, and quick reference. Selecting **"Set up AvaKill"** walks you through:

1. Detects installed agents (claude-code, gemini-cli, cursor, windsurf, openai-codex)
2. Prompts for a template (hooks, default, strict, permissive)
3. Copies the template to `avakill.yaml` and validates it
4. Offers to install hooks for every detected agent

### Non-interactive alternative

Use `avakill init` for scripted or CI setups:

```bash
avakill init --template default
avakill init --template strict --output policies/production.yaml
avakill init --scan    # Scan project for sensitive files and generate deny rules
avakill init --mode hooks  # Protection mode: hooks, launch, mcp, all
```

### Templates

| Template | Default action | Philosophy |
|----------|---------------|------------|
| `hooks` | `allow` | Blocks catastrophic ops, allows most else |
| `default` | `deny` | Balanced -- allows reads, blocks destructive ops, rate-limits searches |
| `strict` | `deny` | Maximum safety -- explicit allowlist only, rate limits on everything |
| `permissive` | `allow` | Audit mode -- logs everything, blocks only catastrophic operations |

### The default policy

Here's what `default.yaml` actually contains -- 7 rules with cross-agent tool names (abbreviated; see `src/avakill/templates/default.yaml` for the full file):

```yaml
version: "1.0"
default_action: deny

policies:
  - name: block-destructive-ops       # deny delete_*, remove_*, destroy_*, drop_* (+ suffixes)
    tools: ["delete_*", "remove_*", "destroy_*", "drop_*", "*_delete", "*_remove", "*_destroy", "*_drop"]
    action: deny

  - name: block-destructive-sql       # deny DROP/DELETE/TRUNCATE/ALTER on database_*, sql_*, etc.
    tools: ["database_*", "sql_*", "execute_sql", "run_query"]
    action: deny
    conditions: { args_match: { query: ["DROP", "DELETE", "TRUNCATE", "ALTER"] } }

  - name: block-dangerous-shell       # deny rm -rf, sudo, chmod 777, mkfs, > /dev/
    tools: ["shell_execute", "Bash", "run_shell_command", "run_command",  # + Codex + globs
            "shell", "local_shell", "exec_command", "shell_*", "bash_*", "command_*"]
    action: deny
    conditions: { args_match: { command: ["rm -rf", "sudo", "chmod 777", "mkfs", "> /dev/"] } }

  - name: rate-limit-web-search       # 30 calls/minute
    tools: ["web_search", "WebSearch"]
    action: allow
    rate_limit: { max_calls: 30, window: "1m" }

  - name: allow-read-operations       # Claude Code names + generic prefix/suffix globs
    tools: ["Read", "Glob", "Grep", "LS", "WebFetch", "grep_files",
            "search_*", "get_*", "list_*", "read_*", "query_*", "fetch_*", "find_*", "lookup_*",
            "*_search", "*_get", "*_list", "*_read", "*_query", "*_fetch", "*_find", "*_lookup"]
    action: allow

  - name: allow-safe-sql              # after destructive SQL blocked above
    tools: ["database_*", "sql_*", "execute_sql", "run_query"]
    action: allow

  - name: allow-safe-shell            # shell_safe + 19-command allowlist
    tools: ["shell_execute", "Bash", "run_shell_command", "run_command",
            "shell", "local_shell", "exec_command", "shell_*", "bash_*", "command_*"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: [echo, ls, cat, pwd, git, python, pip, npm, node,
                          make, which, whoami, date, uname, head, tail, wc, file, stat]
```

Rules are evaluated top-to-bottom. The first matching rule wins. If nothing matches, `default_action` applies.

### Validate your policy

```bash
$ avakill validate avakill.yaml

Policy Rules: 7 rules (block-destructive-ops, block-destructive-sql,
  block-dangerous-shell, rate-limit-web-search, allow-read-operations,
  allow-safe-sql, allow-safe-shell)
Version: 1.0 | Default action: deny | Total rules: 7

Policy is valid.
```

### LLM-assisted policy creation

Instead of writing YAML manually, you can use any LLM to generate a policy:

```bash
# Generate a self-contained prompt and paste it into any LLM
avakill schema --format=prompt

# Include your tool names for a tailored policy
avakill schema --format=prompt --tools="execute_sql,shell_exec,file_read" --use-case="data pipeline"
```

The prompt includes the full JSON Schema, evaluation rules, and examples. Paste it into any LLM, describe your agent, then validate with `avakill validate generated-policy.yaml`. See [`llm-policy-prompt.md`](internal/llm-policy-prompt.md) for a paste-ready version.

## 2. Add AvaKill to Your Code

### The `@protect` decorator

The fastest integration path. It wraps any function with a policy check -- if the policy denies the call, the function body never runs.

```python
from avakill import Guard, protect, PolicyViolation

guard = Guard(policy="avakill.yaml")

@protect(guard=guard)
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    return f"User {user_id} deleted"

@protect(guard=guard)
def search_users(query: str) -> str:
    """Search for users."""
    return f"Found users matching: {query}"

# This succeeds -- "search_users" matches the "*_search" pattern -> allowed
result = search_users(query="active")
print(result)
# -> Found users matching: active

# This raises -- "delete_user" matches no allow rule -> denied by default
try:
    delete_user(user_id="123")
except PolicyViolation as e:
    print(e)
# -> AvaKill blocked 'delete_user': No matching rule; default action is 'deny'
```

Decorator options:

| Option | Example | Effect |
|--------|---------|--------|
| Auto-detect | `@protect` | Loads `avakill.yaml` from cwd |
| Explicit policy | `@protect(policy="strict.yaml")` | Uses specified file |
| Custom tool name | `@protect(guard=guard, tool_name="db_exec")` | Overrides function name |
| Return None | `@protect(guard=guard, on_deny="return_none")` | Returns `None` instead of raising |
| Custom callback | `@protect(guard=guard, on_deny="callback", deny_callback=fn)` | Calls `fn(tool_name, decision, args, kwargs)` |

Works with both sync and async functions.

### Using `Guard.evaluate()` directly

For more control, use `Guard.evaluate()` in your agent loop:

```python
from avakill import Guard, PolicyViolation

guard = Guard(policy="avakill.yaml")

def agent_loop(tool_name: str, args: dict):
    decision = guard.evaluate(tool=tool_name, args=args)

    if not decision.allowed:
        print(f"Blocked by policy '{decision.policy_name}': {decision.reason}")
        return None

    return execute_tool(tool_name, args)
```

### Sessions

Use sessions to group related calls under an agent and session ID:

```python
with guard.session(agent_id="my-agent") as session:
    session.evaluate(tool="search_users", args={"query": "active"})
    session.evaluate(tool="get_user", args={"id": "456"})
    print(f"Calls made: {session.call_count}")  # -> 2
```

### Audit logging

Add a `SQLiteLogger` to persist every decision to a local database:

```python
from avakill import Guard
from avakill.logging.sqlite_logger import SQLiteLogger

logger = SQLiteLogger("avakill_audit.db")
guard = Guard(policy="avakill.yaml", logger=logger)

# Every evaluate() call is now logged automatically
guard.evaluate(tool="search_users", args={"query": "test"})
```

## 3. Protect AI Coding Agents

AvaKill can protect AI coding agents like Claude Code, Gemini CLI, Cursor, Windsurf, and OpenAI Codex without any code changes. Hook scripts intercept tool calls at the agent level and route them through AvaKill's policy engine.

The fastest path is `avakill guide` > **Hooks & Agents**, which handles detection and installation. Or use the CLI directly:

### Start the daemon

```bash
avakill daemon start --policy avakill.yaml
```

The daemon listens on a Unix socket (`~/.avakill/avakill.sock`) and evaluates tool calls in <5ms.

### Install hooks

```bash
# Install for a specific agent
avakill hook install --agent claude-code

# Or install for all detected agents
avakill hook install --agent all
```

### Check status

```bash
avakill hook list
```

### How it works

```
Agent  ->  Hook Script  ->  AvaKill Daemon  ->  Policy Engine
                 |                                    |
          Translates tool name              Evaluates rules
          (Bash -> shell_execute)           Returns: allow/deny
```

### Canonical tool names

One policy works across all agents thanks to canonical names:

| Agent | Native Name | Canonical Name |
|-------|------------|----------------|
| Claude Code | `Bash` | `shell_execute` |
| Claude Code | `Write` / `Read` | `file_write` / `file_read` |
| Gemini CLI | `run_shell_command` | `shell_execute` |
| Cursor | `shell_command` | `shell_execute` |
| Windsurf | `run_command` | `shell_execute` |

### Recommended hook policy

Use `shell_safe` and `command_allowlist` to control shell access:

```yaml
- name: allow-safe-shell
  tools: ["shell_execute", "Bash", "run_shell_command", "run_command",
          "shell", "local_shell", "exec_command"]
  action: allow
  conditions:
    shell_safe: true
    command_allowlist: [echo, ls, cat, pwd, git, python, pip, npm, node,
                        make, which, whoami, date, uname, head, tail, wc, file, stat]
```

Use `avakill guide` > **Policies** to test tool calls against your policy.

## 4. Monitor and Debug

### View audit logs

```bash
# Show recent events
$ avakill logs

┌──────────────────────── AvaKill Audit Log ────────────────────────┐
│ Time                │ Tool          │ Action │ Policy               │
│ 2026-01-15 14:32:01 │ search_users  │ ALLOW  │ allow-read-operations│
│ 2026-01-15 14:32:03 │ delete_user   │ DENY   │                     │
│ 2026-01-15 14:32:05 │ execute_sql   │ DENY   │ block-destructive-sql│
└─────────────────────────────────────────────────────────────────────┘
3 event(s) shown
```

Filter and format options:

```bash
avakill logs --denied-only              # Only denied events
avakill logs --tool "database_*"        # Filter by tool name (supports globs)
avakill logs --since 1h                 # Events from the last hour
avakill logs --agent my-agent           # Filter by agent
avakill logs --json                     # JSON output for piping to jq
avakill logs tail                       # Follow new events in real-time
```

### Run the dashboard

Launch the real-time terminal dashboard with `avakill dashboard`. It shows live safety overview, streaming tool calls, and top denied tools.

```bash
avakill dashboard --db avakill_audit.db     # Custom database path
avakill dashboard --refresh 1.0             # Refresh interval in seconds
avakill dashboard --policy avakill.yaml     # Policy file to monitor
avakill dashboard --watch                   # Auto-reload on policy change
```

Keyboard shortcuts: `q` quit, `r` reload policy, `c` clear events.

### Test tool calls from the CLI

```bash
# Via the daemon
echo '{"tool": "shell_execute", "args": {"command": "rm -rf /"}}' | avakill evaluate --agent cli
# Exit code 2 (denied)

# Standalone (no daemon needed)
echo '{"tool": "file_read", "args": {"path": "README.md"}}' | avakill evaluate --agent cli --policy avakill.yaml
# Exit code 0 (allowed)
```

Exit codes: `0` = allowed, `2` = denied, `1` = error.

## Going Further

### OS sandboxing

Add OS-level containment on top of policy enforcement:

```bash
avakill profile list                                          # See available agent profiles
avakill launch --agent aider --dry-run                        # Test sandbox restrictions
avakill launch --agent aider --policy avakill.yaml -- aider   # Launch with OS sandbox
```

The `avakill guide` TUI also has sections for signing, compliance, MCP wrapping, and approvals.

### Reference

- **[Policy Reference](policy-reference.md)** -- YAML format, conditions, rate limiting, examples
- **[CLI Reference](cli-reference.md)** -- all commands and flags
- **[API Reference](api-reference.md)** -- Python SDK documentation
- **[Framework Integrations](internal/framework-integrations.md)** -- OpenAI, Anthropic, LangChain, MCP
- **[Security Hardening](internal/security-hardening.md)** -- signing, self-protection, OS-level enforcement
- **[Troubleshooting](internal/troubleshooting.md)** -- common issues and solutions
