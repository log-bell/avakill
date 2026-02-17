# Getting Started

AgentGuard is a safety firewall for AI agents. You define policies in YAML; AgentGuard intercepts tool calls and blocks anything outside those boundaries.

This guide gets you from zero to a working policy in under 5 minutes.

## Installation

```bash
pip install agentguard
```

Install with framework-specific extras:

```bash
pip install agentguard[openai]       # OpenAI function calling
pip install agentguard[anthropic]    # Anthropic tool use
pip install agentguard[langchain]    # LangChain / LangGraph
pip install agentguard[mcp]          # MCP proxy
pip install agentguard[all]          # Everything
```

From source:

```bash
git clone https://github.com/agentguard/agentguard.git
cd agentguard
pip install -e ".[dev]"
```

## 1. Initialize Your First Policy

Run `agentguard init` to generate a starter policy file:

```bash
$ agentguard init
Which policy template? [default/strict/permissive] (default): default

╭──── AgentGuard Initialized ────╮
│                                │
│  Policy file created: agentguard.yaml
│  Template: default             │
│                                │
╰────────────────────────────────╯

Next steps:
  1. Review and customise agentguard.yaml
  2. Add AgentGuard to your agent code (see snippet above)
  3. Run agentguard dashboard to monitor in real-time
  4. Run agentguard validate to check your policy
```

Three templates are available:

| Template | Default action | Philosophy |
|----------|---------------|------------|
| `default` | `deny` | Balanced — allows reads, blocks destructive ops, rate-limits searches |
| `strict` | `deny` | Maximum safety — explicit allowlist only, rate limits on everything |
| `permissive` | `allow` | Audit mode — logs everything, blocks only catastrophic operations |

```bash
agentguard init --template strict
agentguard init --template permissive
```

You can also specify the output path:

```bash
agentguard init --template strict --output policies/production.yaml
```

## 2. Review the Policy

Open `agentguard.yaml`. Here's what the default template looks like:

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
$ agentguard validate agentguard.yaml

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
from agentguard import Guard, protect, PolicyViolation

# Load the policy
guard = Guard(policy="agentguard.yaml")

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
# → AgentGuard blocked 'delete_user': No matching rule; default action is 'deny'
```

### How the decorator works

1. When `search_users(query="active")` is called, the decorator calls `guard.evaluate(tool="search_users", args={"query": "active"})`.
2. The engine checks each rule. `search_users` matches `*_search` in the `allow-read-operations` rule.
3. The decision is `allowed=True`, so the function runs normally.
4. When `delete_user(user_id="123")` is called, no rule matches. The `default_action` is `deny`, so `PolicyViolation` is raised.

### Decorator options

```python
# Auto-detect policy from agentguard.yaml in the current directory
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
from agentguard import Guard, PolicyViolation

guard = Guard(policy="agentguard.yaml")

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
from agentguard import Guard
from agentguard.logging.sqlite_logger import SQLiteLogger

logger = SQLiteLogger("agentguard_audit.db")
guard = Guard(policy="agentguard.yaml", logger=logger)

# Every evaluate() call is now logged automatically
guard.evaluate(tool="search_users", args={"query": "test"})
```

## 6. View Audit Logs

Query the audit log from the CLI:

```bash
# Show the last 50 events
$ agentguard logs

┌──────────────────────── AgentGuard Audit Log ────────────────────────┐
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
agentguard logs --denied-only

# Filter by tool name (supports globs)
agentguard logs --tool "database_*"

# Events from the last hour
agentguard logs --since 1h

# Filter by agent
agentguard logs --agent my-agent

# JSON output for piping to jq
agentguard logs --json

# Follow new events in real-time (like tail -f)
agentguard logs tail
```

## 7. Run the Dashboard

Launch the real-time terminal dashboard:

```bash
$ agentguard dashboard
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
agentguard dashboard --db agentguard_audit.db  # Custom database path
agentguard dashboard --refresh 1.0              # Refresh interval in seconds
agentguard dashboard --policy agentguard.yaml   # Policy file to monitor
```

## Next Steps

- **[Policy Reference](policy-reference.md)** — full documentation of the YAML policy format, conditions, rate limiting, and environment variable substitution.
- **[Framework Integrations](framework-integrations.md)** — drop-in wrappers for OpenAI, Anthropic, LangChain, CrewAI, and MCP.
- **[MCP Proxy](mcp-proxy.md)** — deploy AgentGuard as a transparent proxy for any MCP server.
