# Getting Started

AvaKill is a safety firewall for AI agents. You define policies in YAML; AvaKill intercepts tool calls and kills anything outside those boundaries.

This guide gets you from zero to a working policy in under 5 minutes.

## Installation

Install globally with `pipx` (recommended):

```bash
pipx install avakill
```

This installs `avakill` in an isolated environment with all CLI commands available system-wide. No virtualenv needed.

### Alternative: install in a virtualenv

If you're integrating AvaKill into a Python project, install it inside your project's virtualenv:

```bash
# Create and activate a virtualenv (skip if you already have one)
python3 -m venv .venv
source .venv/bin/activate

# Install AvaKill
pip install avakill
```

### Optional framework extras

AvaKill ships optional extras for framework-specific integrations. Add them with bracket syntax:

```bash
pip install "avakill[openai]"       # OpenAI function calling
pip install "avakill[anthropic]"    # Anthropic tool use
pip install "avakill[langchain]"    # LangChain / LangGraph
pip install "avakill[mcp]"          # MCP proxy
pip install "avakill[metrics]"      # Prometheus metrics
pip install "avakill[watch]"        # File-watching (policy hot-reload)
pip install "avakill[all]"          # Everything
```

You can combine multiple extras: `pip install "avakill[openai,anthropic,langchain]"`

> **macOS note:** macOS 14+ blocks `pip install` at the system level (PEP 668). Use `pipx` or a virtualenv — bare `pip install avakill` will fail.

> **zsh note:** Quotes around `"avakill[...]"` are required on zsh (the default macOS shell). Bash works with or without them.

### From source

```bash
git clone https://github.com/log-bell/avakill.git
cd avakill
pip install -e ".[dev]"
```

## 1. Set Up Your Policy

### Interactive setup with `avakill setup`

The recommended way to get started:

```bash
avakill setup
```

This walks you through an interactive flow:

1. **Detect agents** -- scans your machine for AI agents across three protection paths
2. **Create policy** -- builds an `avakill.yaml` from a rule catalog you customize interactively
3. **Install hooks** -- wires AvaKill into detected hook agents as a pre-tool-use check
4. **Wrap MCP servers** -- intercepts MCP server traffic through AvaKill's proxy
5. **OS Sandbox guidance** -- shows launch commands for sandbox-capable agents
6. **Enable tracking** -- optionally starts a background service for logging and diagnostics
7. **Verify & summarize** -- validates the generated policy and shows what was configured

#### Step 1: Agent detection

Setup scans for agents across all three enforcement paths:

```
Scanning your machine...

  Agents found:

    Hooks (native agent integration):
      ✓ Claude Code       ~/.claude/
      ✓ Gemini CLI        ~/.gemini/
      · Cursor            not detected
      · Windsurf          not detected
      ✓ OpenAI Codex      ~/.codex/

    MCP Proxy (wrap MCP servers):
      ✓ Claude Desktop    ~/Library/Application Support/Claude/
      · Cline             not detected
      · Continue.dev      not detected

    OS Sandbox (avakill launch):
      ✓ OpenClaw          ~/.openclaw/
      · Aider             not detected
      · SWE-Agent         not detected
```

Each group maps to a different enforcement path. The remaining steps configure each path for the agents that were detected.

#### Step 2: Policy creation

Setup starts with two **essential rules** that are always included:

- **Catastrophic shell commands** -- blocks `rm -rf /`, `mkfs`, `dd if=`, `> /dev/`, fork bombs
- **Catastrophic SQL** -- blocks `DROP DATABASE`/`DROP SCHEMA` via shell and database tools

Then it presents the **rule catalog** -- 81 optional rules across 14 categories:

| Category | Rules | Examples |
|----------|-------|---------|
| Shell Safety | 12 | Dangerous commands, privilege escalation, obfuscation, pipe-to-shell |
| Database Safety | 3 | Destructive SQL, unqualified DML, permission changes |
| Filesystem Protection | 14 | Path-aware deletion, system dir writes, symlink escapes, persistence |
| Tool Safety | 1 | Block `delete_*`, `remove_*`, `destroy_*` tool patterns |
| Secrets & Access | 9 | SSH keys, cloud credentials, secret detection, PATH poisoning |
| Rate Limits | 2 | Web search throttling, agent spawning limits |
| Version Control | 3 | Force push, branch deletion, credential commits |
| Supply Chain | 2 | Registry manipulation, postinstall scripts |
| Network & Exfiltration | 8 | Encode-transmit chains, DNS exfil, SSH, firewall changes |
| Cloud & Infrastructure | 6 | Resource deletion, Docker, container escape, backup deletion |
| AI Agent Safety | 5 | MCP poisoning, self-modification, tool rate limits |
| OS Hardening | 16 | macOS SIP/TCC/Gatekeeper, Linux kernel/MAC, Windows Defender/UAC/LSASS |

63 of these are pre-selected by default. You toggle rules on and off by number:

```
What else should AvaKill block?
Type numbers to toggle, 'a' for all, Enter to confirm.

Shell Safety  Dangerous commands, privilege escalation, obfuscation
──────────────────────────────────────────────────
   1. ✓ Dangerous shell commands
      Block rm -rf, sudo, chmod 777
   2. [ ] Package install approval
      Require approval for pip install, npm install -g, brew install
   3. [ ] Shell command allowlist
      Only allow approved shell commands (echo, ls, git, python, ...)
   ...
```

After rule selection, you choose a **default action** for tool calls that don't match any rule:

```
Default action (when no rule matches):

  1. allow  Log and allow unmatched calls (recommended)
  2. deny   Block anything not explicitly allowed (stricter)
```

Setup then offers to **scan your project** for sensitive files (`.env`, database files, keys, credentials) and adds protective deny rules for anything it finds.

If you selected any configurable rate limit rules, setup prompts you to customize the thresholds:

```
Tool call rate limit — currently 500 calls/60m
Customize max calls? (500):
```

At the end you'll see something like:

```
✓ Created avakill.yaml (67 rules, default: deny)
```

#### Step 3: Hook installation

For each detected hook agent, setup shows the exact config file it will modify:

```
Install hooks for your detected agents?

  This adds AvaKill as a pre-tool-use check. Your agents will work
  normally — AvaKill only intervenes when a tool call matches a
  block rule.

  • Claude Code     → ~/.claude/settings.json
  • Gemini CLI      → .gemini/settings.json
  • OpenAI Codex    → ~/.codex/config.toml

Install? [y/n] (y):
```

Each hook is smoke-tested after installation to verify `avakill` is on your PATH. If you skip this step, you can install later with `avakill hook install --agent all`.

#### Step 4: MCP wrapping

If MCP-capable agents were detected (Claude Desktop, Cline, Continue.dev), setup offers to wrap their MCP servers:

```
Wrap MCP servers for your detected agents?

  This intercepts all MCP server traffic through AvaKill's proxy.
  Your MCP servers work normally — AvaKill scans requests and
  responses for policy violations.

  ✓ Claude Desktop    already wrapped
```

If servers are already wrapped, setup reports their status. Unwrapped servers are listed with a count of how many will be wrapped. You can skip and wrap later with `avakill mcp-wrap --agent all`.

#### Step 5: OS Sandbox guidance

If sandbox-capable agents were detected (OpenClaw, Aider, SWE-Agent), setup shows how to launch them:

```
OS Sandbox agents detected

  These agents are protected by running them through AvaKill's
  OS-level sandbox. No config changes needed — just launch with:

  • OpenClaw        avakill launch --agent openclaw
```

No configuration is needed -- OS sandboxing is applied at launch time.

#### Step 6: Activity tracking

Setup offers to start a lightweight background service that powers diagnostics and monitoring:

```
Enable activity tracking?

  This runs a lightweight background service that powers:
    • avakill fix        See why something was blocked
    • avakill logs       View agent activity history
    • avakill dashboard  Live monitoring

  Without it, hooks still protect you — you just won't have
  history or diagnostics.

Enable? [y/n] (y):
```

Activity tracking is optional. Hooks, MCP wrapping, and OS sandboxing all enforce your policy regardless. You can enable it later with `avakill tracking on`.

#### Step 7: Summary

Setup validates the policy and prints a summary of everything that was configured:

```
✓ Policy valid  (67 rules, default: deny)

─────────────────────────────────────────────────────

Setup complete. Your agents are now protected.

  Policy:     avakill.yaml (67 rules)
  Tracking:   off
  Hooks:      Claude Code, Gemini CLI, OpenAI Codex
  MCP:        Claude Desktop
  Sandbox:    OpenClaw (protect with: avakill launch --agent openclaw)

If something gets blocked:
  Run  avakill fix            to see why and how to fix it
  Run  avakill rules          to add, remove, or create rules
  Edit avakill.yaml        to change your rules by hand

Enable activity tracking anytime: avakill tracking on

─────────────────────────────────────────────────────
```

### Validate your policy

Whether generated by `avakill setup` or written by hand:

```bash
$ avakill validate avakill.yaml

Policy Rules: 67 rules (block-catastrophic-shell, block-catastrophic-sql-shell, ...)
Version: 1.0 | Default action: deny | Total rules: 67

Policy is valid.
```

### Manage rules with `avakill rules`

After setup, use `avakill rules` to modify your policy without re-running the full wizard or editing YAML by hand.

#### Browse and toggle catalog rules

```bash
avakill rules
```

Opens the same interactive catalog from setup, pre-populated with your current selections. Custom rules and scan-generated rules are preserved — only catalog rules are toggled.

#### List current rules

```bash
avakill rules list
```

Shows every rule in your policy with its source:

```
Policy: avakill.yaml (67 rules, default: deny)
┌────┬──────────────────────────────┬────────┬──────────┬───────────────┐
│  # │ Name                         │ Action │ Source   │ Tools         │
├────┼──────────────────────────────┼────────┼──────────┼───────────────┤
│  1 │ block-catastrophic-shell     │ deny   │ base     │ shell_*, Ba.. │
│  2 │ block-dangerous-shell        │ deny   │ catalog  │ shell_*, Ba.. │
│  … │ ...                          │        │          │               │
│ 66 │ my-custom-rule               │ deny   │ custom   │ Bash          │
│ 67 │ log-all                      │ allow  │ system   │ *             │
└────┴──────────────────────────────┴────────┴──────────┴───────────────┘
  3 base · 60 catalog · 1 custom · 1 system
```

Sources: **base** (always included), **catalog** (from the rule catalog), **scan** (auto-detected sensitive files), **custom** (your hand-written rules), **system** (log-all trailer).

#### Create a custom rule

```bash
avakill rules create
```

An interactive wizard that walks you through:

1. **Name** — e.g. `block-internal-api`
2. **Tools** — pick from presets (shell, file write, file read, database, all) or enter custom patterns
3. **Action** — `deny`, `allow`, or `require_approval`
4. **Conditions** — optional argument matching (e.g. block commands containing `curl evil.com`)
5. **Rate limit** — optional max calls per time window
6. **Message** — optional message shown when the rule triggers

The wizard previews the rule as YAML, then appends it to your policy (before `log-all` if present) and validates.

**Example: block a specific API call**

```
$ avakill rules create

  Rule name: block-internal-api
  Tools: 1 (Shell tools)
  Action: 1 (deny)
  Add argument matching? y
    Argument name: command
    Substrings to match: curl internal.corp, wget internal.corp
    Add another condition? n
  Add rate limiting? n
  Message: Internal API access blocked.
  Add this rule to avakill.yaml? y

  ✓ Added "block-internal-api" to avakill.yaml
```

### LLM-assisted policy creation

Instead of writing YAML by hand, you can have any LLM generate a policy for you. AvaKill produces a self-contained prompt (~900 lines) that includes the full JSON Schema, evaluation rules, anti-patterns, and three example policies — everything an LLM needs to write valid YAML without external docs.

**Step 1: Generate the prompt**

```bash
# Basic — works with any LLM
avakill schema --format=prompt

# Tailored — includes your actual tool names and use case
avakill schema --format=prompt --tools="execute_sql,shell_exec,file_read" --use-case="data pipeline"
```

The `--tools` flag is the most useful — it tells the LLM exactly which tools exist in your system so it writes rules for them instead of generic examples.

**Step 2: Paste it into an LLM and describe what you want**

Copy the output and paste it into Claude, ChatGPT, or any other LLM. Then describe your agent:

> "Generate a policy for a code assistant that can read files, run shell commands, and query a PostgreSQL database. Block destructive SQL and dangerous shell commands. Allow everything else."

The LLM will output a complete `avakill.yaml` — no markdown fences, no explanations, just valid YAML.

**Step 3: Review and activate**

Save the LLM's output to a file, then use AvaKill's review/approve workflow:

```bash
# Save the output as a proposed policy (not avakill.yaml directly)
# Then validate it
avakill validate policy.proposed.yaml

# Review — shows a formatted rule table
avakill review policy.proposed.yaml

# Approve — copies it to avakill.yaml (human-only, agents can't run this)
avakill approve policy.proposed.yaml
```

The review/approve step is intentional — LLM-generated policies always go through human review before activation. See [`llm-policy-prompt.md`](internal/llm-policy-prompt.md) for a paste-ready version of the prompt.

## 2. Add AvaKill to Your Code

Section 1 protects third-party agents you run from the command line. This section is for developers building their own agents or tool-calling applications in Python — chatbots, automation pipelines, custom LangChain agents, internal tools. You embed AvaKill as a library directly in your code so every tool call passes through policy evaluation before it executes. The `Guard` class loads and evaluates policies in-process — no daemon or background service required. You'll need an `avakill.yaml` policy file (created in Section 1 via `avakill init`, or written by hand).

Here's a minimal policy the examples below depend on:

```yaml
# avakill.yaml
version: "1"
default_action: deny

policies:
  - name: allow-search
    tools: ["*_search"]
    action: allow

  - name: allow-get
    tools: ["get_*"]
    action: allow
```

With `default_action: deny`, only tools matching an explicit allow rule can run. The `*_search` pattern allows `search_users`, while `delete_user` matches nothing and is denied.

### The `@protect` decorator

The fastest integration path. It wraps any function with a policy check — if the policy denies the call, the function body never runs. The decorator uses the function name as the tool name by default.

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

Works with both sync and async functions.

Decorator options:

| Option | Example | Effect |
|--------|---------|--------|
| Auto-detect | `@protect` | Loads `avakill.yaml` from cwd |
| Explicit policy | `@protect(policy="strict.yaml")` | Uses specified file |
| Custom tool name | `@protect(guard=guard, tool_name="db_exec")` | Overrides function name |
| Return None | `@protect(guard=guard, on_deny="return_none")` | Returns `None` instead of raising |
| Custom callback | `@protect(guard=guard, on_deny="callback", deny_callback=fn)` | Calls `fn(tool_name, decision, args, kwargs)` |

### Using `Guard.evaluate()` directly

`@protect` is best when your tools are Python functions you own. When you dispatch calls dynamically — tool names arrive as strings at runtime, like in an agent loop — use `Guard.evaluate()` for more control.

`Guard.evaluate()` returns a `Decision` object with fields including `.allowed`, `.action`, `.policy_name`, `.reason`, and others.

```python
from avakill import Guard, PolicyViolation

guard = Guard(policy="avakill.yaml")

def agent_loop(tool_name: str, args: dict):
    """Your main loop that receives tool names and dispatches them."""
    decision = guard.evaluate(tool=tool_name, args=args)

    if not decision.allowed:
        print(f"Blocked by policy '{decision.policy_name}': {decision.reason}")
        return None

    return execute_tool(tool_name, args)  # your application's tool dispatcher
```

### Sessions

Sessions group related calls under one agent/session ID. This enables per-session rate limiting (so limits reset between conversations) and groups audit log entries together for debugging.

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

See the [API Reference](api-reference.md) for the full `Guard` constructor options, `Decision` fields, and framework integrations.

## 3. Protect AI Coding Agents

This section covers off-the-shelf coding agents — Claude Code, Gemini CLI, Cursor, Windsurf, and OpenAI Codex. AvaKill protects them through hook scripts (small executables the agent calls before running each tool) that evaluate every tool call against your policy. No Python code required — just an `avakill.yaml` policy file from Section 1 (or written by hand) and one install command.

Two paths to get started:

- **`avakill setup`** (recommended) — interactive wizard that creates a policy and installs hooks in one pass (covered in Section 1)
- **`avakill hook install`** — targeted, scriptable; installs hooks for agents you specify

### Install hooks

```bash
# Install for a specific agent
avakill hook install --agent claude-code

# Or install for all detected agents
avakill hook install --agent all
```

If you already ran `avakill setup`, hooks are installed. Use `avakill hook install` when you want to add a single agent later or script the setup in CI.

### Check status

After installing, verify the hooks are active:

```bash
avakill hook list
```

### How hooks evaluate

When an agent makes a tool call, the installed hook intercepts it. The hook translates the agent's native tool name to a canonical name (e.g. Claude Code's `Bash` becomes `shell_execute`), evaluates it against your policy, and returns allow or deny to the agent.

Hooks work standalone — no daemon required. Each hook follows this fallback chain to find a policy source:

1. **Self-protection** — hardcoded checks run first (blocks attempts to disable AvaKill itself)
2. **`AVAKILL_POLICY` env var** — if set, loads that file and evaluates in-process
3. **Running daemon** — connects to `~/.avakill/avakill.sock` if a daemon is running
4. **Auto-discover** — looks for `avakill.yaml` or `avakill.yml` in the current directory
5. **Fail-closed** — if `AVAKILL_FAIL_CLOSED=1` is set and no policy was found, denies the call
6. **Fail-open** — otherwise, allows the call and prints a warning to stderr

Fail-open is the default so AvaKill never blocks your workflow before you've configured it. Once your policy is in place, set `AVAKILL_FAIL_CLOSED=1` for production:

```bash
export AVAKILL_FAIL_CLOSED=1
```

The daemon is an optional enhancement — it adds audit logging and shared evaluation across agents, and powers `avakill logs`. Start it with `avakill daemon start --policy avakill.yaml` when you want those features.

### Canonical tool names

AvaKill normalizes agent-specific tool names so one policy works across all agents. For example, Claude Code's `Bash`, Gemini CLI's `run_shell_command`, and Codex's `shell` all become `shell_execute`. The same applies to file operations (`file_read`, `file_write`, `file_edit`) and other tool categories.

See the [CLI Reference](cli-reference.md) for the full canonical name mapping table.

### Recommended hook policy

Use `shell_safe` and `command_allowlist` to control shell access:

- **`shell_safe`** — blocks common destructive patterns (`rm -rf /`, `chmod 777`, pipe to `sh`, etc.)
- **`command_allowlist`** — restricts which commands can run at all

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

See the [Policy Reference](policy-reference.md) for the full list of conditions.

Your coding agents are now protected by AvaKill hooks. Section 4 covers monitoring — viewing audit logs and testing tool calls from the CLI.

## 4. Monitor and Debug

This section covers two tools for visibility into what AvaKill is doing: audit logs (`avakill logs`) and CLI-based tool call testing (`avakill evaluate`).

Audit logging requires a running daemon (`avakill daemon start`) or, if you're using the Python API from Section 2, a `SQLiteLogger` attached to your Guard. Both write to a SQLite database (default: `avakill_audit.db`) that `avakill logs` reads from.

### View audit logs

```bash
$ avakill logs

┌──────────────────────────────────── AvaKill Audit Log ─────────────────────────────────────┐
│ Time                │ Tool          │ Action │ Policy                │ Agent    │ Reason     │
│ 2026-01-15 14:32:01 │ search_users  │ ALLOW  │ allow-read-operations │ cli      │            │
│ 2026-01-15 14:32:03 │ delete_user   │ DENY   │                       │ cli      │ no match…  │
│ 2026-01-15 14:32:05 │ execute_sql   │ DENY   │ block-destructive-sql │ cli      │ SQL cont…  │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
3 event(s) shown
```

Common filters for narrowing results:

```bash
avakill logs --denied-only              # Only denied events
avakill logs --tool "database_*"        # Filter by tool name (supports globs)
avakill logs --since 1h                 # Events from the last hour
avakill logs --agent my-agent           # Filter by agent
avakill logs --json                     # JSON output for piping to jq
avakill logs tail                       # Follow new events in real-time
```

### Test tool calls from the CLI

When developing or debugging your policy, test specific tool calls without running an agent:

```bash
# Test a dangerous command (should be denied)
echo '{"tool": "shell_execute", "args": {"command": "rm -rf /"}}' | avakill evaluate --agent cli
# Exit code 2 (denied)

# Test a safe read (should be allowed)
echo '{"tool": "file_read", "args": {"path": "README.md"}}' | avakill evaluate --agent cli --policy avakill.yaml
# Exit code 0 (allowed)
```

The `--agent cli` flag identifies the source of the call for logging purposes — it appears in the Agent column of `avakill logs`.

Exit codes: `0` = allowed, `2` = denied, `1` = error.

For the full set of options, see the [CLI Reference](cli-reference.md) (`avakill logs`, `avakill evaluate`). For writing and tuning rules, see the [Policy Reference](policy-reference.md).

## Going Further

You now have a working policy, hooks that enforce it, and visibility into what's happening.

### OS sandboxing

Hooks enforce your policy at the tool-call level — they intercept and block before the tool runs. OS sandboxing adds a second layer underneath: it restricts what the agent process itself can do at the operating-system level (filesystem access, network, process creation). Even if a tool call slips past policy, the sandbox catches it.

AvaKill ships sandbox profiles for Linux (Landlock), macOS (sandbox-exec), and Windows (AppContainer). Each profile defines what an agent is allowed to touch:

```bash
avakill profile list                                          # See available agent profiles
avakill profile show aider                                    # See what a profile restricts
avakill launch --agent aider --dry-run                        # Test sandbox restrictions
avakill launch --agent aider --policy avakill.yaml -- aider   # Launch with OS sandbox
```

### What's next

Run `avakill --help` to see all available commands grouped by category. For advanced topics:

- **Signing & verification** — `avakill keygen`, `avakill sign`, `avakill verify`
- **Compliance frameworks** — `avakill compliance report`, `avakill compliance gaps`
- **MCP proxy wrapping** — `avakill mcp-wrap`
- **Approval workflows** — `avakill approvals`
- **Daemon configuration** — `avakill daemon start`

### Reference

- **[Policy Reference](policy-reference.md)** -- YAML format, conditions, rate limiting, examples
- **[CLI Reference](cli-reference.md)** -- all commands and flags
- **[API Reference](api-reference.md)** -- Python SDK documentation
