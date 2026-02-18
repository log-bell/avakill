# Getting Started

AvaKill is a safety firewall for AI agents. You define policies in YAML; AvaKill intercepts tool calls and kills anything outside those boundaries.

This guide gets you from zero to a working policy in under 5 minutes.

## Installation

```bash
pip install avakill
```

Install with framework-specific extras:

```bash
pip install avakill[openai]       # OpenAI function calling
pip install avakill[anthropic]    # Anthropic tool use
pip install avakill[langchain]    # LangChain / LangGraph
pip install avakill[mcp]          # MCP proxy
pip install avakill[all]          # Everything
```

From source:

```bash
git clone https://github.com/avakill/avakill.git
cd avakill
pip install -e ".[dev]"
```

## 1. Initialize Your First Policy

Run `avakill init` to generate a starter policy file:

```bash
$ avakill init
Which policy template? [default/strict/permissive] (default): default

╭──── AvaKill Initialized ────╮
│                                │
│  Policy file created: avakill.yaml
│  Template: default             │
│                                │
╰────────────────────────────────╯

Next steps:
  1. Review and customise avakill.yaml
  2. Add AvaKill to your agent code (see snippet above)
  3. Run avakill dashboard to monitor in real-time
  4. Run avakill validate to check your policy
```

Three templates are available:

| Template | Default action | Philosophy |
|----------|---------------|------------|
| `default` | `deny` | Balanced — allows reads, blocks destructive ops, rate-limits searches |
| `strict` | `deny` | Maximum safety — explicit allowlist only, rate limits on everything |
| `permissive` | `allow` | Audit mode — logs everything, blocks only catastrophic operations |

```bash
avakill init --template strict
avakill init --template permissive
```

You can also specify the output path:

```bash
avakill init --template strict --output policies/production.yaml
```

### LLM-Assisted Policy Creation

Instead of writing YAML manually, you can use any LLM to generate a policy:

```bash
# Generate a self-contained prompt and paste it into any LLM
avakill schema --format=prompt

# Include your tool names for a tailored policy
avakill schema --format=prompt --tools="execute_sql,shell_exec,file_read" --use-case="data pipeline"
```

The prompt includes the full JSON Schema, evaluation rules, examples, and common mistakes to avoid. Copy it into ChatGPT, Claude, Gemini, or any other LLM, then describe your agent and its tools. Validate the output with:

```bash
avakill validate generated-policy.yaml
```

> See [`llm-policy-prompt.md`](llm-policy-prompt.md) for a paste-ready prompt you can use without installing AvaKill.

## 2. Review the Policy

Open `avakill.yaml`. Here's what the default template looks like:

```yaml
version: "1.0"
default_action: deny

policies:
  # Allow read-only operations
  - name: allow-read-operations
    tools: ["*_read", "*_get", "*_list", "*_search", "*_query"]
    action: allow

  # Block destructive SQL
  - name: block-destructive-sql
    tools: ["database_*", "sql_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
    message: "Destructive SQL operations require manual execution"

  # Block dangerous shell commands
  - name: block-dangerous-shell
    tools: ["shell_*", "bash_*", "command_*"]
    action: deny
    conditions:
      args_match:
        cmd: ["rm -rf", "sudo", "chmod 777", "mkfs", "> /dev/"]

  # Rate limit search and code execution
  - name: rate-limit-search
    tools: ["web_search", "code_execute"]
    action: allow
    rate_limit:
      max_calls: 30
      window: "1m"

  # Require approval for sensitive operations
  - name: require-approval-sensitive
    tools: ["email_send", "file_delete", "api_delete"]
    action: require_approval
```

Rules are evaluated top-to-bottom. The first matching rule wins. If nothing matches, `default_action` applies.

Validate your policy file at any time:

```bash
$ avakill validate avakill.yaml

┌─────────────────────────────── Policy Rules ───────────────────────────────┐
│  #  │ Name                      │ Action           │ Rate Limit │
│  1  │ allow-read-operations     │ allow            │ -          │
│  2  │ block-destructive-sql     │ deny             │ -          │
│  3  │ block-dangerous-shell     │ deny             │ -          │
│  4  │ rate-limit-search         │ allow            │ 30/1m      │
│  5  │ require-approval-sensitive│ require_approval │ -          │
└───────────────────────────────────────────────────────────────────────────┘
╭─ Policy Summary ─╮
│ Version:        1.0
│ Default action: deny
│ Total rules:    5
╰──────────────────╯

Policy is valid.
```

## 3. Protect Your First Function

The fastest integration path is the `@protect` decorator. It wraps any function with a policy check — if the policy denies the call, the function body never runs.

```python
from avakill import Guard, protect, PolicyViolation

# Load the policy
guard = Guard(policy="avakill.yaml")

@protect(guard=guard)
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    return f"User {user_id} deleted"

@protect(guard=guard)
def search_users(query: str) -> str:
    """Search for users."""
    return f"Found users matching: {query}"

# This succeeds — "search_users" matches the "*_search" pattern → allowed
result = search_users(query="active")
print(result)
# → Found users matching: active

# This raises — "delete_user" matches no allow rule → denied by default
try:
    delete_user(user_id="123")
except PolicyViolation as e:
    print(e)
# → AvaKill blocked 'delete_user': No matching rule; default action is 'deny'
```

### How the decorator works

1. When `search_users(query="active")` is called, the decorator calls `guard.evaluate(tool="search_users", args={"query": "active"})`.
2. The engine checks each rule. `search_users` matches `*_search` in the `allow-read-operations` rule.
3. The decision is `allowed=True`, so the function runs normally.
4. When `delete_user(user_id="123")` is called, no rule matches. The `default_action` is `deny`, so `PolicyViolation` is raised.

### Decorator options

```python
# Auto-detect policy from avakill.yaml in the current directory
@protect
def my_tool():
    ...

# Explicit policy file
@protect(policy="policies/strict.yaml")
def my_tool():
    ...

# Custom tool name (defaults to the function name)
@protect(guard=guard, tool_name="database_execute")
def run_sql(query: str):
    ...

# Return None instead of raising on denial
@protect(guard=guard, on_deny="return_none")
def optional_tool():
    ...

# Custom denial callback
def on_blocked(tool_name, decision, args, kwargs):
    log.warning(f"Blocked: {tool_name}")
    return {"error": "not allowed"}

@protect(guard=guard, on_deny="callback", deny_callback=on_blocked)
def guarded_tool():
    ...
```

The decorator works with both sync and async functions:

```python
@protect(guard=guard)
async def async_search(query: str) -> str:
    result = await db.search(query)
    return result
```

## 4. Use the Guard Directly

For more control, use `Guard.evaluate()` directly in your agent loop:

```python
from avakill import Guard, PolicyViolation

guard = Guard(policy="avakill.yaml")

def agent_loop(tool_name: str, args: dict):
    # Check before executing
    decision = guard.evaluate(tool=tool_name, args=args)

    if not decision.allowed:
        print(f"Blocked by policy '{decision.policy_name}': {decision.reason}")
        return None

    return execute_tool(tool_name, args)
```

Or use `evaluate_or_raise()` for automatic exceptions:

```python
# Raises PolicyViolation if denied, RateLimitExceeded if rate limited
decision = guard.evaluate_or_raise(tool="delete_user", args={"user_id": "123"})
# If we get here, the call was allowed
```

### Sessions

Use sessions to group related calls under an agent and session ID:

```python
with guard.session(agent_id="my-agent") as session:
    session.evaluate(tool="search_users", args={"query": "active"})
    session.evaluate(tool="get_user", args={"id": "456"})
    print(f"Calls made: {session.call_count}")  # → 2
```

## 5. Enable Audit Logging

Add a `SQLiteLogger` to persist every decision to a local database:

```python
from avakill import Guard
from avakill.logging.sqlite_logger import SQLiteLogger

logger = SQLiteLogger("avakill_audit.db")
guard = Guard(policy="avakill.yaml", logger=logger)

# Every evaluate() call is now logged automatically
guard.evaluate(tool="search_users", args={"query": "test"})
```

## 6. View Audit Logs

Query the audit log from the CLI:

```bash
# Show the last 50 events
$ avakill logs

┌──────────────────────── AvaKill Audit Log ────────────────────────┐
│ Time                │ Tool          │ Action │ Policy               │
│ 2025-01-15 14:32:01 │ search_users  │ ALLOW  │ allow-read-operations│
│ 2025-01-15 14:32:03 │ delete_user   │ DENY   │                     │
│ 2025-01-15 14:32:05 │ execute_sql   │ DENY   │ block-destructive-sql│
└─────────────────────────────────────────────────────────────────────┘
3 event(s) shown
```

Filter and format options:

```bash
# Only denied events
avakill logs --denied-only

# Filter by tool name (supports globs)
avakill logs --tool "database_*"

# Events from the last hour
avakill logs --since 1h

# Filter by agent
avakill logs --agent my-agent

# JSON output for piping to jq
avakill logs --json

# Follow new events in real-time (like tail -f)
avakill logs tail
```

## 7. Run the Dashboard

Launch the real-time terminal dashboard:

```bash
$ avakill dashboard
```

The dashboard shows:

- **Safety Overview** — total events, allowed/denied/pending counts with percentages
- **Live Tool Calls** — a streaming table of every intercepted call with timestamps, actions, and matching policies
- **Top Denied Tools** — bar chart of the most frequently blocked tools in the last hour

Keyboard shortcuts:

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Reload policy |
| `c` | Clear events |

Options:

```bash
avakill dashboard --db avakill_audit.db  # Custom database path
avakill dashboard --refresh 1.0              # Refresh interval in seconds
avakill dashboard --policy avakill.yaml   # Policy file to monitor
```

## 8. Protect AI Coding Agents with Hooks

AvaKill can protect AI coding agents like Claude Code, Gemini CLI, Cursor, and Windsurf without any code changes. Hook scripts intercept tool calls at the agent level and route them through AvaKill's policy engine.

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
Agent (e.g., Claude Code)
  │
  ├─ Tool call: Bash("rm -rf /")
  │
  ▼
Hook Script (avakill-hook-claude-code)
  │
  ├─ Translates tool name: Bash → shell_execute
  ├─ Sends EvaluateRequest to daemon
  │
  ▼
AvaKill Daemon
  │
  ├─ Evaluates against policy
  ├─ Returns: deny
  │
  ▼
Hook Script
  │
  └─ Returns deny to agent → tool call blocked
```

Policies use **canonical tool names** so one policy works across all agents:

| Agent | Native Name | Canonical Name |
|-------|------------|----------------|
| Claude Code | `Bash` | `shell_execute` |
| Claude Code | `Write` | `file_write` |
| Claude Code | `Read` | `file_read` |
| Gemini CLI | `run_shell_command` | `shell_execute` |
| Cursor | `shell_command` | `shell_execute` |
| Windsurf | `run_command` | `shell_execute` |

Write policies using canonical names:

```yaml
policies:
  - name: "block-dangerous-shells"
    tools: ["shell_execute"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777"]
```

## 9. Evaluate Tool Calls from the CLI

You can evaluate tool calls directly without running an agent:

```bash
# Via the daemon
echo '{"tool": "shell_execute", "args": {"command": "rm -rf /"}}' | avakill evaluate --agent cli
# Exit code 2 (denied)

# Standalone (no daemon needed)
echo '{"tool": "file_read", "args": {"path": "README.md"}}' | avakill evaluate --agent cli --policy avakill.yaml
# Exit code 0 (allowed)
```

Exit codes: `0` = allowed, `2` = denied, `1` = error.

## Next Steps

- **[Policy Reference](policy-reference.md)** — full documentation of the YAML policy format, conditions, rate limiting, and environment variable substitution.
- **[Framework Integrations](framework-integrations.md)** — drop-in wrappers for OpenAI, Anthropic, LangChain, CrewAI, and MCP.
- **[MCP Proxy](mcp-proxy.md)** — deploy AvaKill as a transparent proxy for any MCP server.
- **[Security Hardening](security-hardening.md)** — policy signing, self-protection, OS-level hardening, and C-level audit hooks.
- **[Deployment Guide](deployment.md)** — dev → staging → production patterns, Docker, and systemd.
- **[Cookbook](cookbook.md)** — real-world policy recipes for common use cases.
- **[CLI Reference](cli-reference.md)** — complete documentation for all CLI commands.
- **[API Reference](api-reference.md)** — full Python API documentation.
- **[Troubleshooting](troubleshooting.md)** — common issues and solutions.
- **[Native Agent Hooks](framework-integrations.md#native-agent-hooks)** — per-agent hook details for Claude Code, Gemini CLI, Cursor, and Windsurf.
- **[Daemon Deployment](deployment.md#daemon-deployment)** — running the daemon with systemd, monitoring, and SIGHUP reload.
- **[Compliance Reporting](deployment.md#compliance-deployment)** — automated SOC 2, NIST, EU AI Act, and ISO 42001 assessments.
