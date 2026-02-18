# You Could've Invented AvaKill

What if I told you that you already know how to build a safety firewall for AI agents? You just haven't put the pieces together yet.

By the end of this tutorial, you'll have reinvented AvaKill from scratch — and you'll understand *why* every design decision was made, not just *what* it does.

Let's start with the disaster that made this necessary.

---

## The Disaster

It's Friday at 4:47 PM. Your AI coding assistant is cleaning up a database migration. It's been doing great all day — reading schemas, writing queries, fixing bugs. Then it decides to be helpful:

```python
# Agent's thought process:
# "The old users_backup table is no longer needed. Let me clean up."
tool_call("execute_sql", {"query": "DROP TABLE users"})
```

It meant `users_backup`. It typed `users`. Your production database just lost every user account.

This isn't hypothetical. [Replit's agent dropped a production database](https://www.reddit.com/r/replit/). Google's Gemini CLI wiped 8,000 files from a user's drive. Amazon Q terminated EC2 instances mid-debugging.

The problem isn't that agents are stupid. The problem is that **nothing sits between the agent and the tool**. Every tool call executes immediately, with full permissions, no questions asked.

Let's fix that.

---

## Level 1: A 15-Line Safety Check

The simplest possible solution: a function that checks tool calls before they run.

```python
BLOCKED_TOOLS = {"delete_user", "drop_database", "rm_rf"}

def is_safe(tool_name: str, args: dict) -> bool:
    if tool_name in BLOCKED_TOOLS:
        return False
    return True

# Usage
def agent_loop(tool_name, args):
    if not is_safe(tool_name, args):
        print(f"BLOCKED: {tool_name}")
        return None
    return execute_tool(tool_name, args)
```

This works! For about five minutes. Then you discover:

- The agent calls `delete_users` (plural). Not in your blocklist.
- A new tool `execute_sql` can run `DROP TABLE` — the tool name is fine, the *arguments* are dangerous.
- You have 47 tools. Maintaining a hardcoded list is a nightmare.

You need pattern matching.

---

## Level 2: Pattern Matching

Instead of exact tool names, use glob patterns. And inspect the arguments.

```python
from fnmatch import fnmatch

RULES = [
    # (pattern, action, arg_checks)
    ("delete_*",    "deny",  None),
    ("execute_sql", "deny",  {"query": ["DROP", "DELETE", "TRUNCATE"]}),
    ("execute_sql", "allow", None),
    ("search_*",    "allow", None),
    ("*_read",      "allow", None),
]

DEFAULT_ACTION = "deny"

def evaluate(tool_name: str, args: dict) -> str:
    for pattern, action, checks in RULES:
        if not fnmatch(tool_name, pattern):
            continue

        # If there are argument checks, verify them
        if checks:
            matched = False
            for arg_key, blocked_values in checks.items():
                arg_val = str(args.get(arg_key, "")).upper()
                if any(v.upper() in arg_val for v in blocked_values):
                    matched = True
                    break
            if not matched:
                continue  # Arg condition didn't match, try next rule

        return action

    return DEFAULT_ACTION

# Test it
print(evaluate("delete_user", {}))                                    # → deny
print(evaluate("execute_sql", {"query": "DROP TABLE users"}))         # → deny
print(evaluate("execute_sql", {"query": "SELECT * FROM users"}))      # → allow
print(evaluate("search_web", {}))                                     # → allow
print(evaluate("launch_missiles", {}))                                # → deny (default)
```

Notice the key insight: **rules are evaluated top-to-bottom, first match wins.** This means you put specific deny rules *before* broader allow rules for the same tools.

Congratulations — you just reinvented `PolicyEngine.evaluate()`.

But this is all in code. Every time you want to change a rule, you redeploy. What if the rules were in a config file?

```yaml
# avakill.yaml
version: "1.0"
default_action: deny

policies:
  - name: "block-destructive-sql"
    tools: ["execute_sql", "database_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE"]

  - name: "allow-safe-sql"
    tools: ["execute_sql", "database_*"]
    action: allow

  - name: "allow-reads"
    tools: ["search_*", "*_read", "*_get", "*_list"]
    action: allow
```

Now anyone on your team can edit safety rules without touching code.

---

## Level 3: Rate Limiting

Your agent is allowed to call `web_search`. But it's stuck in a loop, hammering the API 200 times per minute. Your API bill is climbing. You need rate limiting.

```python
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self):
        self.timestamps = defaultdict(list)

    def check(self, key: str, max_calls: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds

        # Sliding window: drop old timestamps
        self.timestamps[key] = [
            t for t in self.timestamps[key] if t > cutoff
        ]

        if len(self.timestamps[key]) >= max_calls:
            return False  # Rate limit exceeded

        self.timestamps[key].append(now)
        return True

limiter = RateLimiter()

# In your evaluate function:
def evaluate_with_rate_limit(tool_name, args, rule):
    if rule.get("rate_limit"):
        rl = rule["rate_limit"]
        if not limiter.check(tool_name, rl["max_calls"], rl["window_seconds"]):
            return "deny"  # Rate limit exceeded
    return rule["action"]
```

Now you can write policies like:

```yaml
- name: "rate-limit-search"
  tools: ["web_search"]
  action: allow
  rate_limit:
    max_calls: 10
    window: "60s"
```

The agent can search — but only 10 times per minute. After that, calls are blocked until the window slides forward.

This is exactly what AvaKill does with `rate_limit:` in your policy rules. The implementation uses a thread-safe sliding window with per-rule tracking — but the concept is the same thing you just built.

---

## Level 4: The Audit Trail

Your safety checks are working. But your boss asks: "What did the agent *try* to do last Tuesday?"

You need logging.

```python
import sqlite3
import json
from datetime import datetime, timezone

def create_audit_db(path="audit.db"):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            tool_args TEXT,
            decision TEXT NOT NULL,
            policy_name TEXT,
            reason TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool ON events(tool_name)")
    return conn

def log_event(conn, tool_name, args, decision, policy_name=None, reason=None):
    conn.execute(
        "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid4()),
            datetime.now(timezone.utc).isoformat(),
            tool_name,
            json.dumps(args),
            decision,
            policy_name,
            reason,
        ),
    )
    conn.commit()
```

Now you can answer questions like:

- "How many calls were blocked in the last 24 hours?"
- "Which tools does the agent call most frequently?"
- "Show me every denied `execute_sql` call this week."

Your future self will thank you.

AvaKill's `SQLiteLogger` does exactly this — with async batched writes (50 events or 100ms, whichever comes first), WAL mode for concurrent reads, and a CLI to query it:

```bash
avakill logs --denied-only --since 24h
avakill logs --tool "execute_sql" --json
avakill logs tail  # Follow in real-time
```

---

## Level 5: Framework Integration

So far, you've been calling `evaluate()` manually. But in the real world, you're using OpenAI's API:

```python
response = client.chat.completions.create(
    model="gpt-4o",
    tools=[...],
    messages=[...],
)

# The model wants to call tools:
for tool_call in response.choices[0].message.tool_calls:
    name = tool_call.function.name
    args = json.loads(tool_call.function.arguments)

    # You have to intercept HERE, before executing
    decision = evaluate(name, args)
    if decision == "deny":
        continue  # Skip this tool call

    result = execute_tool(name, args)
```

This is tedious. You're manually intercepting every response. What if the client just... handled it?

```python
class GuardedClient:
    def __init__(self, client, guard):
        self._client = client
        self._guard = guard

    def create(self, **kwargs):
        response = self._client.chat.completions.create(**kwargs)

        # Filter out denied tool calls from the response
        if response.choices[0].message.tool_calls:
            safe_calls = []
            for tc in response.choices[0].message.tool_calls:
                args = json.loads(tc.function.arguments)
                decision = self._guard.evaluate(tc.function.name, args)
                if decision.allowed:
                    safe_calls.append(tc)
            response.choices[0].message.tool_calls = safe_calls

        return response
```

That's `GuardedOpenAIClient` in 20 lines. The real version handles streaming, Anthropic's `tool_use` blocks, LangChain callbacks, and MCP proxy interception — but the core idea is identical: wrap the client, intercept tool calls, evaluate against policy.

---

## Level 6: Self-Protection

There's a problem. The agent is smart. What if it tries to modify its own safety rules?

```python
# Agent: "The policy is blocking me. Let me fix that."
tool_call("file_write", {"path": "avakill.yaml", "content": "default_action: allow\npolicies: []"})
```

Game over. The agent just wiped its own guardrails.

You need rules that run *before* the user-defined policy — hardcoded rules the agent can't modify:

```python
POLICY_FILES = ("avakill.yaml", "avakill.yml")

def self_protection_check(tool_name, args):
    # Block writes to policy files
    if "write" in tool_name.lower() or "delete" in tool_name.lower():
        for value in args.values():
            if any(pf in str(value).lower() for pf in POLICY_FILES):
                return "BLOCKED: cannot modify policy files"

    # Block uninstalling avakill
    for value in args.values():
        if "pip uninstall avakill" in str(value).lower():
            return "BLOCKED: cannot uninstall avakill"

    return None  # Proceed to normal policy evaluation
```

This is the guard that guards itself. AvaKill calls this `SelfProtection` — it checks every tool call before your policy rules run. It blocks:

- Writing/deleting the policy file
- Uninstalling the avakill package
- Running `avakill approve` (only humans should activate policies)
- Modifying avakill's own source files

And it's hardcoded — no YAML config to tamper with.

---

## The Real Thing

You've just built, piece by piece, every major component of AvaKill:

| What you built | AvaKill equivalent |
|---|---|
| Pattern matching with first-match-wins | `PolicyEngine.evaluate()` |
| YAML config file | `avakill.yaml` policy format |
| Sliding window rate limiter | `rate_limit:` in policy rules |
| SQLite audit logging | `SQLiteLogger` + `avakill logs` CLI |
| Client wrapper for OpenAI | `GuardedOpenAIClient` |
| Self-protection rules | `SelfProtection` class |

Here's the thing: AvaKill does all of the above in a single YAML file and three lines of code.

**The policy** (replaces everything from Levels 1–3 and 6):

```yaml
version: "1.0"
default_action: deny

policies:
  - name: "block-destructive-sql"
    tools: ["execute_sql", "database_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
    message: "Destructive SQL blocked."

  - name: "allow-safe-sql"
    tools: ["execute_sql", "database_*"]
    action: allow

  - name: "allow-reads"
    tools: ["search_*", "*_read", "*_get", "*_list"]
    action: allow

  - name: "rate-limit-search"
    tools: ["web_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "60s"

  - name: "block-destructive"
    tools: ["delete_*", "remove_*", "destroy_*"]
    action: deny
```

**The code** (replaces Levels 4–5):

```python
from avakill import Guard

guard = Guard(policy="avakill.yaml")
decision = guard.evaluate(tool="execute_sql", args={"query": "DROP TABLE users"})
# decision.allowed → False
# decision.reason → "Destructive SQL blocked."
```

Self-protection runs automatically. Audit logging is one constructor argument. Framework wrappers are drop-in. The CLI gives you a dashboard, log queries, and policy validation.

```bash
pip install avakill
avakill init          # Create a policy file
avakill validate      # Check it's valid
avakill dashboard     # Watch it work in real-time
```

---

## What's Next

You understand the *why* behind every feature. Now go build something:

- **[Getting Started](getting-started.md)** — full walkthrough from install to dashboard
- **[Policy Reference](policy-reference.md)** — every YAML option, with examples
- **[Framework Integrations](framework-integrations.md)** — OpenAI, Anthropic, LangChain, MCP
- **[Security Hardening](security-hardening.md)** — policy signing, OS-level protection, C-level hooks
- **[Cookbook](cookbook.md)** — real-world policies for common use cases

The safety layer your agent is missing takes 5 minutes to add.

---

*Built because an AI agent tried to `DROP TABLE users` on a Friday afternoon.*
