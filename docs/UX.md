# UX Reference: Core User Flow

This document describes the core AvaKill user flow in full technical detail for the UX team. MCP wrapping, Go shim, and Python proxy are out of scope — this covers the **hooks-only** path, which is the only battle-tested integration today.

---

## The Pipeline

```
Install → Create Policy → Start Daemon (optional) → Install Hooks → Work as Normal
```

That's the entire core flow. Five steps. Every command in this doc maps to one of these steps.

---

## Step 1: Install

### Command: `pipx install avakill`

Installs avakill globally. After install, the following binaries are available on PATH:

- `avakill` — the main CLI
- `avakill-hook-claude-code` — Claude Code hook binary
- `avakill-hook-gemini-cli` — Gemini CLI hook binary
- `avakill-hook-cursor` — Cursor hook binary
- `avakill-hook-windsurf` — Windsurf hook binary
- `avakill-hook-openai-codex` — OpenAI Codex hook binary

### First-run behavior

On the very first invocation of `avakill` (any subcommand), a one-time welcome panel is shown:

```
╭─────────────────────────────────────╮
│  AvaKill v0.5.0 installed           │
│                                     │
│  Run avakill guide to get started   │
╰─────────────────────────────────────╯
```

This is written to stderr so it doesn't interfere with piped commands. A marker file (`~/.avakill/.installed`) is created so it only shows once.

### Running `avakill` with no arguments

Prints a gradient ASCII wordmark banner:

```
  █   █  █   █   █   █  █  █     █
  █   █  █   █  █ █  █ █  █     █
  █████  █   █  █ █  ██   █     █
  █   █   █ █  █████  █ █  █     █
  █   █    █   █   █  █  █ █     █
  █   █    █   █   █  █   ██████ ██████

         the ai agent safety firewall

  ────────────────────────────────────
  v0.5.0 β              docs: avakill.com

  run avakill guide to get started  ·  avakill --help for all commands
```

### What's missing from this step

- No indication of what to do next beyond "run avakill guide"
- No auto-detection of agents on the machine
- No prompt to create a policy
- The banner is visually impressive but provides zero actionable guidance

---

## Step 2: Create a Policy

A policy is a YAML file (typically `avakill.yaml` in the project root) that defines rules for allowing, denying, or rate-limiting tool calls.

### Policy structure

```yaml
version: "1.0"
default_action: allow  # or "deny"

policies:
  - name: rule-name
    tools: ["Bash", "shell_execute"]  # tool names or glob patterns
    action: deny                       # allow | deny | require_approval
    conditions:                        # optional
      args_match:
        command: ["rm -rf", "sudo"]
    rate_limit:                        # optional
      max_calls: 30
      window: "1m"
    message: "Human-readable reason"   # optional
```

Rules are evaluated **top-to-bottom, first match wins**. If no rule matches, `default_action` applies.

### Available templates

There are 4 templates. The user should pick one as a starting point, then customize.

| Template | `default_action` | Philosophy | Best for |
|----------|------------------|------------|----------|
| **hooks** | `allow` | Block catastrophic ops, allow everything else | Hook users (recommended) |
| **default** | `deny` | Allowlist — only listed tools work | SDK/API users |
| **strict** | `deny` | Reads allowed, writes and shell require approval | High-security environments |
| **permissive** | `allow` | Allow everything, log everything | Development/audit |

#### hooks template rules (the recommended default)

1. `block-dangerous-shell` — denies `rm -rf /`, `mkfs`, fork bombs, `dd if=`, `> /dev/` in any shell tool
2. `block-destructive-sql` — denies `DROP DATABASE`, `DROP SCHEMA`
3. `approve-package-installs` — requires approval for `pip install`, `npm install -g`, `brew install`
4. `rate-limit-agents` — rate-limits agent spawning (Task tool) to 20/min
5. `log-all` — allows everything else

#### default template rules

1. `block-destructive-ops` — denies `delete_*`, `remove_*`, `destroy_*`, etc.
2. `block-destructive-sql` — denies DROP/DELETE/TRUNCATE/ALTER in SQL tools
3. `block-dangerous-shell` — denies `rm -rf`, `sudo`, `chmod 777`, etc. in shell tools
4. `rate-limit-web-search` — 30 calls/min for web search tools
5. `allow-read-operations` — allows Read, Glob, Grep, search_*, get_*, list_*, etc.
6. `allow-safe-sql` — allows non-destructive SQL
7. `allow-safe-shell` — allows shell commands that pass `shell_safe` check + are in a command allowlist (echo, ls, cat, git, python, pip, npm, node, make, etc.)
8. Everything else → **denied** (falls through to `default_action: deny`)

This is what caused the user's Write tool to get blocked — Write isn't in any allow rule.

#### strict template rules

1. `allow-reads-only` — allows read tools, rate-limited to 10/min
2. `writes-require-approval` — Write, Edit, write_file, apply_patch → require_approval
3. `execution-requires-approval` — Bash, shell, run_command → require_approval (with shell_safe check)
4. `block-destructive` — denies *_delete, *_drop, *_destroy, *_remove

#### permissive template rules

1. `block-drop-database` — denies DROP DATABASE/SCHEMA
2. `block-rm-rf-root` — denies `rm -rf /`
3. `log-everything` — allows everything else with logging

### Commands for creating a policy

#### `avakill init`

**Status**: PRODUCTION (never human-tested E2E)

```bash
avakill init                              # interactive — prompts for template
avakill init --template hooks             # non-interactive — uses hooks template
avakill init --template hooks --scan      # also scans for sensitive files (.env, credentials, etc.)
avakill init --template hooks --output custom-policy.yaml
```

**Interactive flow (when stdin is a TTY):**
1. If `avakill.yaml` already exists, asks to overwrite (default: no)
2. Scans for framework dependencies (openai, anthropic, langchain, mcp)
3. Prompts: "Which policy template?" — choices: hooks, default, strict, permissive (default: hooks)
4. Copies template to `avakill.yaml`
5. If `--scan`, detects sensitive files and prepends deny rules
6. Shows summary panel with: file path, template name, detected sensitive files, detected frameworks, quickstart code snippet
7. Detects installed AI agents and suggests `avakill hook install --agent all`
8. Shows numbered next steps

**Non-interactive flow (piped/scripted):**
- Uses `hooks` template (no prompt)
- No overwrite prompt — fails if file exists

**Current UX problems:**
- Doesn't install hooks (just suggests it)
- Doesn't mention the daemon
- Shows framework integration snippets (SDK) that aren't relevant to hook users
- The mode selector (hooks/launch/mcp/all) is confusing and only appears interactively when `--template` wasn't given on the CLI

#### `avakill guide` → Section 1: "Set up AvaKill"

**Status**: BATTLE-TESTED

This is the setup wizard buried inside the guide menu. To reach it:
1. Run `avakill guide`
2. See a 7-item main menu
3. Choose option 1 ("Set up AvaKill")

Then:
1. Detects agents on the machine (shows list)
2. If `avakill.yaml` already exists, shows "Policy already exists" and suggests validate/hook install/dashboard
3. If no policy: shows 4 template options as a numbered list (hooks, default, strict, permissive)
4. Copies template, validates it
5. If agents detected, asks "Install hooks now?" (default: yes)
6. Installs hooks for all detected agents
7. Shows "you're protected" with next steps

**This is the closest thing to the correct flow**, but it's buried behind a menu and doesn't mention the daemon.

#### `avakill quickstart`

**Status**: PRODUCTION (never human-tested), **NOT REGISTERED IN CLI** (removed from help, source kept)

An older linear flow that was replaced by `avakill guide`. Asks: which agent → protection level (strict/moderate/permissive) → scan? → generates policy → installs hooks. Uses confusing level names ("moderate" = default template, "permissive" = hooks template).

### Commands for inspecting/editing a policy

#### `avakill validate`

**Status**: BATTLE-TESTED

```bash
avakill validate                          # validates avakill.yaml in cwd
avakill validate /path/to/policy.yaml     # validates a specific file
```

Checks: YAML syntax, schema validity, rule count, shadowed rules. Exits 0 on valid, 1 on invalid. Useful as a CI gate.

**Output on success:**
```
✓ Policy is valid
  Template: hooks
  Rules: 5
  Default action: allow
```

**Output on failure:**
```
✗ Policy validation failed
  Error: unknown action 'blok' in rule 'my-rule'
```

#### `avakill review`

**Status**: BATTLE-TESTED

```bash
avakill review avakill.yaml
avakill review avakill.proposed.yaml
```

Pretty-prints a policy with syntax-highlighted YAML, a rules summary table, and next steps. Read-only — doesn't modify anything.

#### `avakill evaluate` (for testing rules)

**Status**: BATTLE-TESTED

Test specific tool calls against your policy before going live:

```bash
# Will this get blocked?
echo '{"tool": "Bash", "args": {"command": "rm -rf /"}}' | avakill evaluate --policy avakill.yaml

# JSON output
echo '{"tool": "Write", "args": {"path": "/tmp/test.txt"}}' | avakill evaluate --policy avakill.yaml --json

# Test rate limiting — simulate 50 rapid calls
echo '{"tool": "Bash", "args": {"command": "curl api.example.com"}}' | avakill evaluate --policy avakill.yaml --simulate-burst 50
```

**Exit codes**: 0 = allow, 2 = deny, 1 = error

**Output (stderr):**
```
allow: Matched rule 'allow-safe-shell'
```
or
```
deny: Dangerous shell command blocked. [block-dangerous-shell]
```

#### `avakill schema --format=prompt`

**Status**: BATTLE-TESTED

Generates an LLM prompt containing the full policy schema, so you can ask an AI to help write rules:

```bash
avakill schema --format=prompt
avakill schema --format=prompt --tools="Bash,Write,Read" --use-case="code review agent"
avakill schema --format=prompt -o avakill-prompt.txt
```

### The propose/review/approve workflow (for policy changes)

When the policy is live and you want to change it:

1. Write changes to a `.proposed.yaml` file (agent can do this)
2. Human reviews: `avakill review avakill.proposed.yaml`
3. Human activates: `avakill approve avakill.proposed.yaml`

The `approve` command validates the proposed policy, creates a `.bak` backup of the current policy, and atomically replaces it. If signing keys are configured (`AVAKILL_SIGNING_KEY` env var), it auto-signs.

```bash
avakill approve avakill.proposed.yaml           # interactive confirm
avakill approve avakill.proposed.yaml --yes     # skip confirm (scripting)
avakill approve avakill.proposed.yaml --target /etc/avakill/avakill.yaml
```

**Self-protection**: Agents cannot run `avakill approve`. Only humans can activate policy changes. The hook will block any attempt by an agent to run this command.

---

## Step 3: Start the Daemon (Optional)

The daemon is a persistent evaluation server running on a Unix domain socket (`~/.avakill/avakill.sock`). It's **optional** — hooks work without it.

### With daemon vs. without daemon

| | Without daemon (standalone) | With daemon |
|---|---|---|
| **How hooks evaluate** | Each hook spawns an embedded Guard in-process | Hooks connect to daemon via Unix socket |
| **Speed** | ~10-50ms per call (Python process startup) | ~1-5ms per call (socket round-trip) |
| **Audit logging** | No centralized logging | `--log-db` enables SQLite audit trail |
| **Policy reload** | Reads policy file on every call | Caches policy, reload via dashboard |
| **Required for** | Nothing — standalone works fine | `avakill logs`, `avakill fix`, `avakill dashboard` |

### Commands

#### `avakill daemon start`

```bash
# Minimal
avakill daemon start --policy avakill.yaml

# With audit logging (recommended — enables fix, logs, dashboard)
avakill daemon start --policy avakill.yaml --log-db avakill_audit.db

# Foreground (for debugging)
avakill daemon start --foreground --policy avakill.yaml

# Full options
avakill daemon start --policy avakill.yaml --log-db avakill_audit.db --approval-db ~/.avakill/approvals.db
```

**Behavior:**
- Checks if daemon is already running (uses PID file at `~/.avakill/avakill.pid`)
- If already running: prints "Daemon already running (PID X)" and exits 1
- If `--foreground`: runs in current process, prints "Listening on /path/to/sock"
- Otherwise: forks a background process, waits 1 second for startup, reports PID
- If startup fails: captures stderr and shows error

**Output:**
```
Starting AvaKill daemon (policy: avakill.yaml)...
Daemon started (PID 12345).
```

#### `avakill daemon status`

```bash
avakill daemon status
```

**Output (running):**
```
Daemon is running (PID 12345).
Socket: /Users/you/.avakill/avakill.sock
```

**Output (not running):**
```
Daemon is not running.
```

#### `avakill daemon stop`

```bash
avakill daemon stop
```

**Output:**
```
Sent SIGTERM to daemon (PID 12345).
```

If no daemon: "No running daemon found." (exit 1)

---

## Step 4: Install Hooks

Hooks are pre-tool-use interceptors that evaluate every tool call against the policy before it executes.

### Agent detection

AvaKill auto-detects installed agents by checking:

| Agent | How it's detected |
|-------|-------------------|
| Claude Code | `~/.claude/` directory exists OR `claude` binary on PATH |
| Gemini CLI | `~/.gemini/` directory exists OR `gemini` binary on PATH |
| Cursor | `/Applications/Cursor.app` (macOS) OR `cursor` on PATH OR `~/.cursor/` exists |
| Windsurf | `/Applications/Windsurf.app` (macOS) OR `windsurf` on PATH OR `~/.codeium/windsurf/` exists |
| OpenAI Codex | `~/.codex/` directory exists OR `codex` binary on PATH |

### Commands

#### `avakill hook list`

Shows a table of all agents with detection and hook installation status:

```
┌──────────────┬──────────┬────────────────┐
│ Agent        │ Detected │ Hook Installed │
├──────────────┼──────────┼────────────────┤
│ claude-code  │ yes      │ yes            │
│ gemini-cli   │ yes      │ no             │
│ cursor       │ no       │ no             │
│ windsurf     │ no       │ no             │
│ openai-codex │ no       │ no             │
└──────────────┴──────────┴────────────────┘
```

#### `avakill hook install --agent <name>`

```bash
avakill hook install --agent claude-code
avakill hook install --agent gemini-cli
avakill hook install --agent windsurf
avakill hook install --agent openai-codex
avakill hook install --agent all            # all detected agents
```

**What it does per agent:**

| Agent | Config file written | Hook event | Format |
|-------|-------------------|------------|--------|
| Claude Code | `~/.claude/settings.json` | `PreToolUse` | `{"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "/path/to/avakill-hook-claude-code"}]}]}}` |
| Gemini CLI | `.gemini/settings.json` (cwd) | `BeforeTool` | `{"hooks": {"BeforeTool": [{"matcher": ".*", "hooks": [{"type": "command", "command": "/path/to/avakill-hook-gemini-cli"}]}]}}` |
| Cursor | `.cursor/hooks.json` (cwd) | `beforeShellExecution` | `{"hooks": {"beforeShellExecution": [{"command": "/path/to/avakill-hook-cursor"}]}}` |
| Windsurf | `~/.codeium/windsurf/hooks.json` | `pre_run_command` | `{"hooks": {"pre_run_command": [{"command": "/path/to/avakill-hook-windsurf", "show_output": true}]}}` |
| OpenAI Codex | `~/.codex/config.toml` | `before_tool_use` | ⚠️ Pending upstream — Codex CLI doesn't support pre-execution hooks yet. Generates exec policy `.rules` files as stopgap. |

**Behavior:**
1. Resolves the absolute path to the hook binary (checks PATH, then Python env's bin/ directory)
2. Creates config directory if it doesn't exist
3. Reads existing config (or creates empty JSON)
4. Appends hook entry to the correct event section (idempotent — won't duplicate)
5. Writes config back
6. Runs a smoke test (executes the hook binary with empty stdin, checks it doesn't 127)

**Output:**
```
Installed hook for claude-code -> /Users/you/.claude/settings.json
  Command: /Users/you/.local/bin/avakill-hook-claude-code
  Smoke test: passed

Important: The hook will evaluate tool calls against your AvaKill policy.
  The default template blocks tools not in its allowlist, which may lock out your agent.
  For hooks, use the hooks template: avakill init --template hooks
  Or set AVAKILL_POLICY to a policy file for standalone mode (no daemon required).
```

**Warning states:**
- If the hook binary can't be found on PATH: "Could not find 'avakill-hook-claude-code' on PATH or in the active Python environment. The hook may fail silently."
- If smoke test fails: "Smoke test failed: '/path/to/avakill-hook-claude-code' did not execute successfully. Hook calls will fail at runtime."
- For Codex: "Codex CLI does not yet support pre-execution hooks."

#### `avakill hook uninstall --agent <name>`

```bash
avakill hook uninstall --agent claude-code
avakill hook uninstall --agent all
```

Removes the AvaKill entry from the agent's config. Does not delete the config file.

**Output:**
```
Removed hook for claude-code
```

If no hook found: "No hook found for claude-code"

---

## Step 5: Work as Normal

Once hooks are installed and a policy exists, the agent works normally. Every tool call is intercepted transparently.

### What happens on every tool call

When the agent (e.g. Claude Code) tries to use a tool (e.g. Write), the hook binary runs this **fallback chain**:

```
1. Self-protection check (hardcoded, no policy needed)
   → Blocks: modifying avakill source, uninstalling avakill, running avakill approve,
     modifying policy files, killing the daemon
   → If blocked: deny immediately

2. AVAKILL_POLICY env var set?
   → Evaluate against that policy file (standalone mode)

3. Daemon running?
   → Evaluate via Unix socket (fast, centralized)

4. avakill.yaml or avakill.yml in cwd?
   → Evaluate against local policy file (standalone mode)

5. No policy source found
   → If AVAKILL_FAIL_CLOSED=1: deny
   → Otherwise: allow with stderr warning
```

### What the user sees

**When a tool call is allowed:** Nothing. The tool executes normally. The user never knows AvaKill is there.

**When a tool call is denied (Claude Code example):**

```
● Write(tempfile)
  ├ PreToolUse:Write hook returned blocking error
  ├ No matching rule; default action is 'deny'. Run `avakill fix` for recovery steps.
  └ Error: No matching rule; default action is 'deny'. Run `avakill fix` for recovery steps.
```

The deny message includes:
- The reason (e.g. "Dangerous shell command blocked", "No matching rule; default action is 'deny'")
- The policy rule name in brackets (e.g. `[block-dangerous-shell]`, `[self-protection]`)
- A nudge to run `avakill fix` for recovery steps

**When a tool call is denied (Gemini CLI):**
- Exit code 2
- Reason written to stderr (no stdout)

**When a tool call is denied (Cursor):**
- JSON on stdout: `{"agentMessage": "Blocked by AvaKill: <reason>. Run avakill fix for recovery steps."}`

**When a tool call is denied (Windsurf):**
- Reason written to stderr
- Warning: if Windsurf doesn't support `require_approval`, it degrades to allow with a stderr warning

### Recovery: `avakill fix`

**Status**: BATTLE-TESTED

When something gets blocked, `avakill fix` explains why and tells you how to fix it.

**Requires**: audit database (daemon must have been started with `--log-db`)

```bash
avakill fix --db avakill_audit.db          # most recent denial
avakill fix --all --db avakill_audit.db    # all recent denials (up to 20)
avakill fix --json --db avakill_audit.db   # machine-readable
```

**What it shows (Rich panel):**

```
╭── Fix ──────────────────────────────────────────╮
│                                                  │
│  Tool: Write                                     │
│  Time: 2026-02-22 15:06:12                       │
│  Reason: No matching rule; default action is     │
│          'deny'                                   │
│                                                  │
│  No matching policy rule                         │
│                                                  │
│    Add an explicit allow rule for this tool.     │
│    Or set default_action: allow in the policy.   │
│    Review current rules: avakill review          │
│                                                  │
│  Run:                                            │
│    $ avakill review                              │
│                                                  │
╰──────────────────────────────────────────────────╯
Add to your avakill.yaml:
  # Add this rule to your avakill.yaml (above existing deny rules):
  - name: allow-Write
    tools: ["Write"]
    action: allow
```

**Recovery hint types:**

| Denial type | Hint type | What it suggests |
|---|---|---|
| No matching rule (default deny) | `add_rule` | Copy-paste YAML snippet to add an allow rule |
| Named policy rule deny | `add_rule` | Shows the rule name, suggests adding an allow rule above it |
| Rate limit exceeded | `wait_rate_limit` | Shows wait time, suggests adjusting rate_limit config |
| Self-protection: policy write | `blocked` | "Stage changes via .proposed.yaml, have human run avakill approve" |
| Self-protection: uninstall | `blocked` | "AI agents cannot remove their own safety guardrails" |
| Self-protection: source mod | `blocked` | "A human administrator must modify avakill source" |
| Require approval | `request_approval` | "Run avakill approve" |

**When no audit DB exists:**
```
Database not found: avakill_audit.db
Enable audit logging:
  Daemon:  avakill daemon start --log-db avakill_audit.db
  Python:  Guard(policy='avakill.yaml', logger=SQLiteLogger('avakill_audit.db'))
```

### Monitoring: `avakill logs`

**Status**: BATTLE-TESTED

```bash
avakill logs --db avakill_audit.db                    # recent events
avakill logs --db avakill_audit.db --denied-only      # only blocks
avakill logs --db avakill_audit.db --tool Bash         # filter by tool
avakill logs --db avakill_audit.db --since 5m          # last 5 minutes
avakill logs --db avakill_audit.db --json --limit 2    # JSON (limited)
avakill logs --db avakill_audit.db tail                # live stream
avakill logs --db avakill_audit.db --denied-only tail  # filter + tail
```

### Monitoring: `avakill dashboard`

**Status**: BATTLE-TESTED

```bash
avakill dashboard --db avakill_audit.db
avakill dashboard --db avakill_audit.db --policy avakill.yaml --watch
avakill dashboard --db avakill_audit.db --refresh 1.0
```

Rich TUI with: live event list, allow/deny stats, denied-tools bar chart. Keyboard: `q` quit, `r` reload policy, `c` clear events.

### Human-in-the-loop approvals

For policies using `action: require_approval`:

```bash
avakill approvals list                          # show pending requests
avakill approvals grant 81e01fc7-304            # approve (12-char ID prefix)
avakill approvals reject 81e01fc7-304           # reject
avakill approvals grant abc --approver team     # custom approver name
```

**Flow:**
1. Tool call matches a `require_approval` rule → exits 2 (same as deny to the agent)
2. Human runs `avakill approvals list` → sees pending request with 12-char ID
3. Human runs `avakill approvals grant <id>` → request is approved
4. Next time the same tool call fires → auto-allowed with `[approved]` reason

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AVAKILL_POLICY` | Path to policy file (overrides cwd auto-discovery) | None |
| `AVAKILL_FAIL_CLOSED` | Set to `1` to deny when no policy source found | `0` (fail-open) |
| `AVAKILL_SIGNING_KEY` | Ed25519 private key (hex) for auto-signing on approve | None |
| `AVAKILL_VERIFY_KEY` | Ed25519 public key (hex) for signature verification | None |
| `AVAKILL_POLICY_KEY` | HMAC-SHA256 key (hex) for signing/verification | None |

---

## Self-Protection

Hardcoded rules that run before any policy evaluation. Cannot be disabled. Blocks:

1. **Policy file modification** — Writing to `avakill.yaml`, `*.proposed.yaml`, or any file containing "avakill" policy content
2. **Source code modification** — Reading/writing avakill's own source files
3. **Uninstall attempts** — Running `pip uninstall avakill`, `pipx uninstall avakill`
4. **Approve command** — Agents cannot run `avakill approve` (only humans)
5. **Daemon kill** — Agents cannot kill the daemon process
6. **Hook config tampering** — Agents cannot modify hook configuration files

Self-protection deny messages include `[self-protection]` tag and the `avakill fix` nudge.

---

## Current UX Problems (for the UX team)

### Onboarding is fragmented

Three overlapping entry points (`avakill guide`, `avakill init`, `avakill quickstart`) that each do a different subset of the pipeline. None of them walk through all 5 steps linearly.

### No single setup command

The ideal first-time experience should be:
1. Detect what's on my machine
2. Let me pick a protection level
3. Generate the policy
4. Ask if I want the daemon
5. Install hooks
6. Confirm everything works

No command does all of this today.

### Template naming is confusing

"hooks" vs "default" vs "strict" vs "permissive" — users don't know what these mean without reading YAML files. The old `quickstart` used "strict/moderate/permissive" which was even worse ("moderate" secretly mapped to a deny-by-default template).

### The daemon is invisible

Nothing explains when or why you'd want the daemon. The daemon enables `avakill fix`, `avakill logs`, and `avakill dashboard` — but nobody tells the user this. Without the daemon, `avakill fix` just says "database not found" with no explanation of the connection.

### `avakill fix` requires a database that most users don't have

The most common recovery path (`avakill fix`) requires `--db avakill_audit.db`, which requires the daemon to have been started with `--log-db`. Most users won't have done this. The fix command should work without the daemon — it could read the denial reason directly from the most recent hook invocation instead of requiring a database.

### Agent-specific config paths are not surfaced

Gemini CLI config is in `.gemini/settings.json` (cwd-relative). Claude Code config is in `~/.claude/settings.json` (global). Users have no visibility into where their hooks were installed or what the config looks like.

### The deny message is not actionable enough

```
No matching rule; default action is 'deny'. Run `avakill fix` for recovery steps.
```

This tells you what happened but not how to fix it inline. The user has to leave their agent, open a terminal, run `avakill fix --db ...` (which probably doesn't work because no DB), and figure it out. The deny message itself should include a one-liner fix suggestion.

### No "dry run" mode

There's no way to install hooks in a monitoring-only mode where everything is allowed but logged. The permissive template is close, but it still blocks `rm -rf /` and `DROP DATABASE`. A true dry-run/audit-only mode would allow everything and just log.

### No undo story

If hooks are installed and the policy is too restrictive, the agent is effectively locked out. The user needs to know they can:
1. Run `avakill hook uninstall --agent <name>` in a separate terminal
2. Or edit `avakill.yaml` directly to fix the rule
3. Or set `default_action: allow` temporarily

This escape hatch should be prominently documented and ideally surfaced in the deny message.

---

## Command Reference Summary

### Setup (Step 1-4)

| Command | What it does | Status |
|---------|-------------|--------|
| `avakill init --template hooks` | Generate policy file | PRODUCTION |
| `avakill validate` | Check policy syntax | BATTLE-TESTED |
| `avakill review avakill.yaml` | Pretty-print policy | BATTLE-TESTED |
| `avakill evaluate --policy avakill.yaml` | Test a tool call | BATTLE-TESTED |
| `avakill daemon start --policy avakill.yaml --log-db avakill_audit.db` | Start evaluation daemon | BATTLE-TESTED |
| `avakill daemon status` | Check daemon | BATTLE-TESTED |
| `avakill daemon stop` | Stop daemon | BATTLE-TESTED |
| `avakill hook list` | Show agents and hook status | BATTLE-TESTED |
| `avakill hook install --agent all` | Install hooks | BATTLE-TESTED |
| `avakill hook uninstall --agent <name>` | Remove hooks | BATTLE-TESTED |

### Day-to-day (Step 5)

| Command | What it does | Status |
|---------|-------------|--------|
| `avakill fix --db avakill_audit.db` | Why was I blocked? How to fix? | BATTLE-TESTED |
| `avakill logs --db avakill_audit.db` | View audit events | BATTLE-TESTED |
| `avakill logs --db avakill_audit.db tail` | Live stream events | BATTLE-TESTED |
| `avakill dashboard --db avakill_audit.db` | Live TUI dashboard | BATTLE-TESTED |
| `avakill approvals list` | Show pending approval requests | BATTLE-TESTED |
| `avakill approvals grant <id>` | Approve a request | BATTLE-TESTED |
| `avakill approve avakill.proposed.yaml` | Activate new policy | BATTLE-TESTED |

### Advanced (not part of core flow)

| Command | What it does | Status |
|---------|-------------|--------|
| `avakill sign --ed25519 avakill.yaml` | Sign policy | BATTLE-TESTED |
| `avakill verify avakill.yaml` | Verify signature | BATTLE-TESTED |
| `avakill keygen` | Generate signing keypair | BATTLE-TESTED |
| `avakill harden avakill.yaml` | Set OS immutable flag | BATTLE-TESTED |
| `avakill check-hardening avakill.yaml` | Show hardening status | BATTLE-TESTED |
| `avakill schema --format=prompt` | Generate LLM prompt for policy writing | BATTLE-TESTED |
| `avakill compliance report` | SOC 2 / NIST / EU AI Act assessment | BATTLE-TESTED |
| `avakill profile list` | Show agent containment profiles | BATTLE-TESTED |
