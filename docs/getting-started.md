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

AvaKill can protect AI coding agents like Claude Code, Gemini CLI, Windsurf, and OpenAI Codex without any code changes. Hook scripts intercept tool calls at the agent level and route them through AvaKill's policy engine.

The fastest path is `avakill setup`, which handles detection and installation. Or use the CLI directly:

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

### Standalone mode (no daemon)

Hooks work without a running daemon. When the daemon is unreachable, each hook evaluates policies in-process using this fallback chain:

1. Connect to daemon socket (`~/.avakill/avakill.sock`)
2. If unreachable, load policy from `avakill.yaml` in cwd and evaluate locally
3. If no policy file found, **allow** the call (fail-open, the default)

To change the default to **fail-closed** (deny when no policy is available):

```bash
export AVAKILL_FAIL_CLOSED=1
```

With `AVAKILL_FAIL_CLOSED=1`, tool calls are denied when both the daemon and local policy file are unavailable. This is recommended for production environments.

### Canonical tool names

One policy works across all agents thanks to canonical names:

| Agent | Native Name | Canonical Name |
|-------|------------|----------------|
| Claude Code | `Bash` | `shell_execute` |
| Claude Code | `Write` / `Read` | `file_write` / `file_read` |
| Gemini CLI | `run_shell_command` | `shell_execute` |
| Gemini CLI | `read_file` / `write_file` / `edit_file` | `file_read` / `file_write` / `file_edit` |
| Gemini CLI | `search_files` / `list_files` | `file_search` / `file_list` |
| Gemini CLI | `web_search` / `web_fetch` | `web_search` / `web_fetch` |
| Windsurf | `run_command` | `shell_execute` |
| Windsurf | `write_code` / `read_code` | `file_write` / `file_read` |
| Windsurf | `mcp_tool` | *(pass-through)* |
| OpenAI Codex | `shell` | `shell_execute` |
| OpenAI Codex | `apply_patch` / `read_file` | `file_write` / `file_read` |
| OpenAI Codex | `list_dir` / `grep_files` | `file_list` / `content_search` |

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

Use `avakill evaluate` to test tool calls against your policy.

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

The `avakill guide` TUI has additional sections for signing, compliance, MCP wrapping, and approvals.

### Reference

- **[Policy Reference](policy-reference.md)** -- YAML format, conditions, rate limiting, examples
- **[CLI Reference](cli-reference.md)** -- all commands and flags
- **[API Reference](api-reference.md)** -- Python SDK documentation
- **[Framework Integrations](internal/framework-integrations.md)** -- OpenAI, Anthropic, LangChain, MCP
- **[Security Hardening](internal/security-hardening.md)** -- signing, self-protection, OS-level enforcement
- **[Troubleshooting](internal/troubleshooting.md)** -- common issues and solutions
