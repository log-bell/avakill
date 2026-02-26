# CLI Reference

AvaKill provides a command-line interface for policy management, security, monitoring, and integration. All commands use [Rich](https://rich.readthedocs.io/) for formatted terminal output.

```bash
avakill [--version] <command> [options]
```

## Commands by Category

**Tier 1 — Core:** [setup](#avakill-setup) | [tracking](#avakill-tracking) | [validate](#avakill-validate) | [evaluate](#avakill-evaluate) | [fix](#avakill-fix) | [hook install](#avakill-hook-install) | [hook uninstall](#avakill-hook-uninstall) | [hook list](#avakill-hook-list) | [Hook Binaries](#hook-binaries) | [avakill-shim](#avakill-shim) | [guide](#avakill-guide)

**Tier 2 — Operations:** [logs](#avakill-logs) | [logs tail](#avakill-logs-tail) | [dashboard](#avakill-dashboard) | [daemon start](#avakill-daemon-start) | [daemon stop](#avakill-daemon-stop) | [daemon status](#avakill-daemon-status) | [review](#avakill-review) | [approve](#avakill-approve) | [approvals list](#avakill-approvals-list) | [approvals grant](#avakill-approvals-grant) | [approvals reject](#avakill-approvals-reject)

**Tier 3 — Security:** [keygen](#avakill-keygen) | [sign](#avakill-sign) | [verify](#avakill-verify) | [harden](#avakill-harden) | [check-hardening](#avakill-check-hardening)

**Tier 4 — Advanced (shipped):** [schema](#avakill-schema) | [profile list](#avakill-profile-list) | [profile show](#avakill-profile-show) | [compliance report](#avakill-compliance-report) | [compliance gaps](#avakill-compliance-gaps) | [mcp-wrap](#avakill-mcp-wrap) | [mcp-unwrap](#avakill-mcp-unwrap)

**Tier 4 — Advanced (future release):** [enforce landlock](#avakill-enforce-landlock) | [enforce sandbox](#avakill-enforce-sandbox) | [enforce windows](#avakill-enforce-windows) | [enforce tetragon](#avakill-enforce-tetragon) | [launch](#avakill-launch) | [mcp-proxy](#avakill-mcp-proxy) | [metrics](#avakill-metrics)

---

## avakill setup

Interactive setup — one command to go from zero to protected.

```
avakill setup
```

No arguments or options. Launches a 5-step interactive flow:

| Step | What it does |
|------|-------------|
| 1. Detect agents | Scans for Claude Code, Gemini CLI, Cursor, Windsurf, OpenAI Codex |
| 2. Create policy | Generates `avakill.yaml` from the `hooks` template |
| 3. Install hooks | Registers AvaKill with detected agents |
| 4. Activity tracking | Optionally enables the tracking daemon |
| 5. Summary | Shows what was configured |

Non-interactive use: `avakill init --template hooks`

---

## avakill tracking

Manage activity tracking (daemon lifecycle with user-friendly language).

```
avakill tracking <on|off|status>
```

| Subcommand | Description |
|------------|-------------|
| `on` | Enable tracking — starts the background daemon |
| `off` | Disable tracking — stops the daemon, preserves audit history |
| `status` | Show whether tracking is active and audit DB location |

---

## avakill guide

Interactive guide — setup, learning, and reference.

```
avakill guide
```

No arguments or options. Launches a navigable menu:

| # | Section | What it covers |
|---|---------|----------------|
| 1 | Set up AvaKill | Detect agents, select template, generate policy, install hooks |
| 2 | Policies | Writing, validating, testing policies |
| 3 | Hooks & Agents | Install hooks, agent profiles, self-protection |
| 4 | Signing & Hardening | Sign/verify policies, immutable flags |
| 5 | Monitoring | Dashboard, logs, fix |
| 6 | Advanced | Compliance, approvals, MCP wrapping, daemon, schema |
| 7 | Quick Reference | All commands at a glance |

For detailed learning and reference, see also [avakill setup](#avakill-setup) which is the recommended entry point for new users.

> `avakill init` and `avakill quickstart` are deprecated. Use `avakill setup` for first-time configuration.

---

## avakill validate

Validate a policy file for correctness.

```
avakill validate [POLICY_FILE]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `POLICY_FILE` | `avakill.yaml` | Path to the policy file |

Checks YAML syntax, schema validation, and prints a summary table of all rules. Exits `0` if valid, `1` if invalid — safe for CI pipelines.

If `AVAKILL_POLICY_KEY` is set, also checks the signature.

**Examples:**

```bash
# Validate default policy file
avakill validate

# Validate a specific file
avakill validate policies/production.yaml

# Use in CI
avakill validate avakill.yaml || exit 1
```

---

## avakill evaluate

Evaluate a tool call against the policy.

```
avakill evaluate --agent AGENT [--socket PATH] [--tcp-port PORT] [--policy FILE] [--json] [--simulate-burst N]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--agent` | `cli` | Agent identifier (e.g., `cli`, `claude-code`, `gemini-cli`) |
| `--socket` | `~/.avakill/avakill.sock` | Unix domain socket path for daemon mode (Linux/macOS) |
| `--tcp-port` | *(none)* | TCP port for daemon mode (default on Windows) |
| `--policy` | *(none)* | Policy file path (for standalone mode, bypasses daemon) |
| `--json` | `false` | Output full JSON response |
| `--simulate-burst` | *(none)* | Simulate N rapid calls to test rate limiting (requires `--policy`) |

Reads a JSON object from stdin with `tool` and `args` fields. Connects to the daemon via Unix socket (Linux/macOS) or TCP localhost (Windows); use `--policy` for standalone evaluation without a daemon.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Tool call allowed |
| `2` | Tool call denied |
| `1` | Error (invalid input, daemon unreachable without fallback) |

**Examples:**

```bash
# Evaluate via daemon
echo '{"tool": "shell_execute", "args": {"command": "rm -rf /"}}' | avakill evaluate --agent cli

# Evaluate standalone (no daemon needed)
echo '{"tool": "file_write", "args": {"path": "/etc/passwd"}}' | avakill evaluate --agent cli --policy avakill.yaml

# JSON output
echo '{"tool": "file_read", "args": {"path": "README.md"}}' | avakill evaluate --agent cli --json

# Test rate limiting with 50 rapid calls
echo '{"tool": "Bash", "args": {"cmd": "curl example.com"}}' | avakill evaluate --policy avakill.yaml --simulate-burst 50
```

---

## avakill fix

Show recovery steps for recent policy denials.

```
avakill fix [--last] [--all] [--db PATH] [--json]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--last` | *(default behavior)* | Show only the most recent denial |
| `--all` | `false` | Show all recent denials (up to 20) |
| `--db` | `avakill_audit.db` | Path to the audit database |
| `--json` | `false` | Output as JSON |

Queries the audit database for denied events and generates actionable recovery suggestions — including copy-pasteable commands and YAML snippets you can add to your policy.

**Examples:**

```bash
# Show fix for the most recent denial
avakill fix

# Show fixes for all recent denials
avakill fix --all

# Machine-readable output
avakill fix --json

# Custom audit database
avakill fix --db /var/log/avakill/audit.db
```

---

## avakill hook install

Register AvaKill hooks in an agent's configuration.

```
avakill hook install --agent AGENT
```

| Option | Default | Description |
|--------|---------|-------------|
| `--agent` | *(required)* | Agent to install hook for: `claude-code`, `gemini-cli`, `cursor`, `windsurf`, `openai-codex`, or `all` |

Writes the appropriate hook configuration to the agent's config directory.

**Per-agent configuration paths:**

| Agent | Config Path |
|-------|-------------|
| Claude Code | `~/.claude/settings.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Cursor | `~/.cursor/hooks.json` |
| Windsurf | `~/.windsurf/hooks.json` |
| OpenAI Codex | `~/.codex/config.toml` |

**Examples:**

```bash
avakill hook install --agent claude-code
avakill hook install --agent openai-codex
avakill hook install --agent all
```

---

## avakill hook uninstall

Remove AvaKill hooks from an agent's configuration.

```
avakill hook uninstall --agent AGENT
```

| Option | Default | Description |
|--------|---------|-------------|
| `--agent` | *(required)* | Agent to uninstall hook for: `claude-code`, `gemini-cli`, `cursor`, `windsurf`, `openai-codex`, or `all` |

**Example:**

```bash
avakill hook uninstall --agent claude-code
```

---

## avakill hook list

Show detected agents and hook installation status.

```
avakill hook list
```

No options. Displays a table of all supported agents with their detection and hook installation status.

**Example:**

```bash
$ avakill hook list
     Agent Hook Status
┌─────────────┬──────────┬────────────────┐
│ Agent       │ Detected │ Hook Installed │
├─────────────┼──────────┼────────────────┤
│ claude-code │ yes      │ yes            │
│ gemini-cli  │ no       │ no             │
│ cursor      │ yes      │ no             │
│ windsurf    │ no       │ no             │
│ openai-codex│ no       │ no             │
└─────────────┴──────────┴────────────────┘
```

---

### Hook Binaries

Installed alongside `avakill`. Called by agent hooks — you don't invoke these directly.

| Binary | Agent |
|--------|-------|
| avakill-hook-claude-code | Claude Code |
| avakill-hook-gemini-cli | Gemini CLI |
| avakill-hook-cursor | Cursor |
| avakill-hook-windsurf | Windsurf |
| avakill-hook-openai-codex | OpenAI Codex |

---

## avakill-shim

MCP stdio proxy — sits between an MCP client and an upstream MCP server, intercepting JSON-RPC traffic for policy evaluation, tool-hash verification, and emergency kill switch enforcement. This is a standalone Go binary, separate from the Python `avakill` CLI.

```
avakill-shim [flags] -- <command> [args...]
```

Everything after `--` is the upstream MCP server command.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--socket PATH` | `~/.avakill/avakill.sock` | Daemon socket path for evaluation |
| `--policy PATH` | *(none)* | Policy file for in-process evaluation (bypasses daemon) |
| `--verbose` | `false` | Detailed stderr diagnostics |
| `--diagnose` | `false` | Run preflight checks and exit (JSON output) |
| `--version` | `false` | Print version and exit |
| `--pin-tools` | `false` | Pin tool definitions on first `tools/list` response and exit |
| `--kill` | `false` | Create kill switch sentinel file and exit |
| `--kill-reason REASON` | *(none)* | Reason for kill switch activation (used with `--kill`) |
| `--unkill` | `false` | Remove kill switch sentinel file and exit |
| `--killswitch-file PATH` | `~/.avakill/killswitch` | Kill switch sentinel file path |

### Kill switch

The kill switch is an emergency mechanism that instantly denies ALL tool calls. It has two independent triggers:

| Trigger | Scope | Engage | Disengage |
|---------|-------|--------|-----------|
| Sentinel file | Machine-wide (all shim instances) | `avakill-shim --kill` or create `~/.avakill/killswitch` | `avakill-shim --unkill` or delete the file |
| Signal | Per-process | `kill -USR1 <pid>` | `kill -USR2 <pid>` |

The shim is engaged if *either* trigger is active. SIGUSR2 only clears the per-process signal engagement — it does not remove the sentinel file or affect other shim instances.

### Diagnose

`--diagnose` runs preflight checks and prints JSON to stdout. Checks: daemon reachability, kill switch status (including engagement timestamp), upstream command resolution, policy file validity, shell environment recovery, and tool manifest state.

### Examples

```bash
# Wrap an MCP server with policy evaluation
avakill-shim --policy avakill.yaml -- npx @modelcontextprotocol/server-filesystem /tmp

# Use daemon for evaluation
avakill-shim --socket ~/.avakill/avakill.sock -- python mcp_server.py

# Pin tool definitions (one-shot, exits after first tools/list)
avakill-shim --pin-tools -- npx @modelcontextprotocol/server-filesystem /tmp

# Emergency kill — deny all tool calls immediately
avakill-shim --kill --kill-reason "compromised session detected"

# Resume normal operation
avakill-shim --unkill

# Per-process kill via signal
kill -USR1 $(pgrep -f avakill-shim)

# Per-process resume via signal
kill -USR2 $(pgrep -f avakill-shim)

# Run preflight checks
avakill-shim --diagnose -- npx @modelcontextprotocol/server-filesystem /tmp

# Verbose mode for debugging
avakill-shim --verbose --policy avakill.yaml -- python mcp_server.py
```

---

## avakill logs

Query and display audit logs.

```
avakill logs [--db PATH] [--tool PATTERN] [--limit N] [--denied-only] [--agent ID]
             [--session ID] [--since DURATION] [--json]
avakill logs tail [--db PATH]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--db` | `avakill_audit.db` | Path to the audit database |
| `--tool` | *(all)* | Filter by tool name (supports globs) |
| `--limit` | `50` | Maximum number of entries |
| `--denied-only` | `false` | Show only denied events |
| `--agent` | *(all)* | Filter by agent ID |
| `--session` | *(all)* | Filter by session ID |
| `--since` | *(all)* | Show events after this time (e.g. `1h`, `30m`, `7d`) |
| `--json` | `false` | Output as JSON instead of table |

### avakill logs tail

Follow new audit events in real-time (like `tail -f`).

```
avakill logs tail [--db PATH]
```

**Examples:**

```bash
# Show last 50 events
avakill logs

# Only denied events from the last hour
avakill logs --denied-only --since 1h

# Filter by tool pattern
avakill logs --tool "database_*"

# Export as JSON
avakill logs --json > audit-export.json

# Filter by agent
avakill logs --agent my-agent --limit 100

# Follow in real-time
avakill logs tail
```

---

## avakill dashboard

Launch the real-time terminal dashboard.

```
avakill dashboard [--db PATH] [--refresh SECONDS] [--policy PATH] [--watch|--no-watch]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--db` | `avakill_audit.db` | Path to the audit database |
| `--refresh` | `0.5` | Refresh interval in seconds |
| `--policy` | *(none)* | Path to the policy file to monitor |
| `--watch/--no-watch` | `--no-watch` | Auto-reload policy when file changes on disk |

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Reload policy |
| `c` | Clear events |

**Examples:**

```bash
# Default dashboard
avakill dashboard

# Custom database and refresh interval
avakill dashboard --db /var/lib/avakill/audit.db --refresh 1.0

# With policy monitoring and auto-reload
avakill dashboard --policy avakill.yaml --watch
```

---

## avakill daemon start

Start the AvaKill evaluation daemon.

```
avakill daemon start [--policy PATH] [--socket PATH] [--tcp-port PORT] [--log-db PATH] [--approval-db PATH] [--foreground] [--enforce]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--socket` | `~/.avakill/avakill.sock` | Unix domain socket path (Linux/macOS). Also set via `AVAKILL_SOCKET` env var. |
| `--tcp-port` | `19426` | TCP localhost port (default on Windows, optional on Linux/macOS) |
| `--log-db` | *(none)* | Path to the audit database |
| `--approval-db` | `~/.avakill/approvals.db` | Approval request database path |
| `--foreground`, `-f` | `false` | Run in foreground instead of daemonizing |
| `--enforce` | `false` | Apply OS-level enforcement (Landlock/sandbox-exec) |

The daemon evaluates tool calls sent by agent hooks or the `avakill evaluate` command. On Linux/macOS it listens on a Unix domain socket by default; on Windows it uses TCP localhost (port 19426). It creates a PID file at `~/.avakill/avakill.pid`.

**Signal handling:**

| Signal | Action |
|--------|--------|
| `SIGHUP` | Reload the policy file from disk |
| `SIGTERM` | Graceful shutdown |
| `SIGINT` | Graceful shutdown |

**Examples:**

```bash
# Start in background with default settings
avakill daemon start

# Start with explicit policy and logging
avakill daemon start --policy policies/strict.yaml --log-db /var/log/avakill/audit.db

# Start in foreground (for debugging or systemd)
avakill daemon start --foreground

# Start with OS enforcement enabled
avakill daemon start --enforce

# Reload policy without restarting
kill -HUP $(cat ~/.avakill/avakill.pid)
```

---

## avakill daemon stop

Stop the running AvaKill daemon.

```
avakill daemon stop [--socket PATH] [--tcp-port PORT]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--socket` | `~/.avakill/avakill.sock` | Unix domain socket path (Linux/macOS) |
| `--tcp-port` | *(none)* | TCP port |

Sends SIGTERM to the daemon process. Cleans up socket/port and PID files.

**Example:**

```bash
avakill daemon stop
```

---

## avakill daemon status

Check the AvaKill daemon status.

```
avakill daemon status [--socket PATH] [--tcp-port PORT]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--socket` | `~/.avakill/avakill.sock` | Unix domain socket path (Linux/macOS) |
| `--tcp-port` | *(none)* | TCP port |

Reports whether the daemon is running, its PID, and listening address.

**Example:**

```bash
avakill daemon status
# → Daemon is running (PID 12345)
```

---

## avakill review

Review a proposed policy file before activation.

```
avakill review PROPOSED_FILE
```

| Argument | Required | Description |
|----------|----------|-------------|
| `PROPOSED_FILE` | Yes | Path to the proposed policy file |

Validates the YAML, shows a syntax-highlighted view and rules summary, then prints the `avakill approve` command to activate it. Exits `0` if valid, `1` if invalid.

**Example:**

```bash
avakill review avakill.proposed.yaml
# Shows formatted rules table and validation result
# Prints: avakill approve avakill.proposed.yaml
```

---

## avakill approve

Activate a proposed policy file.

```
avakill approve PROPOSED_FILE [--target PATH] [--yes]
```

| Argument/Option | Default | Description |
|-----------------|---------|-------------|
| `PROPOSED_FILE` | *(required)* | Path to the proposed policy file |
| `--target` | `avakill.yaml` | Target filename for the activated policy |
| `--yes`, `-y` | `false` | Skip confirmation prompt |

Validates the proposed policy, then copies it to the target location. This command should only be run by humans — self-protection blocks agents from executing it.

**Examples:**

```bash
# Review then approve
avakill review avakill.proposed.yaml
avakill approve avakill.proposed.yaml

# Skip confirmation
avakill approve avakill.proposed.yaml --yes

# Custom target
avakill approve staging.yaml --target avakill.yaml
```

---

## avakill approvals list

List pending approval requests.

```
avakill approvals list [--db PATH]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--db` | `~/.avakill/approvals.db` | Path to the approvals database |

**Example:**

```bash
avakill approvals list
```

---

## avakill approvals grant

Approve a pending approval request.

```
avakill approvals grant REQUEST_ID [--db PATH] [--approver NAME]
```

| Argument/Option | Default | Description |
|-----------------|---------|-------------|
| `REQUEST_ID` | *(required)* | ID of the approval request |
| `--db` | `~/.avakill/approvals.db` | Path to the approvals database |
| `--approver` | `cli-user` | Name of the approver |

**Example:**

```bash
avakill approvals grant abc123 --approver admin
```

---

## avakill approvals reject

Reject a pending approval request.

```
avakill approvals reject REQUEST_ID [--db PATH] [--approver NAME]
```

| Argument/Option | Default | Description |
|-----------------|---------|-------------|
| `REQUEST_ID` | *(required)* | ID of the approval request |
| `--db` | `~/.avakill/approvals.db` | Path to the approvals database |
| `--approver` | `cli-user` | Name of the approver |

**Example:**

```bash
avakill approvals reject abc123 --approver admin
```

---

## avakill keygen

Generate an Ed25519 keypair for policy signing.

```
avakill keygen
```

No arguments or options. Prints export commands for both keys:

```bash
$ avakill keygen
# Output:
export AVAKILL_SIGNING_KEY=<private-key-hex>   # Keep secret — use in CI/deploy
export AVAKILL_VERIFY_KEY=<public-key-hex>     # Deploy to production
```

Store the signing key in your secrets manager. Only the verify key needs to be on production machines.

---

## avakill sign

Sign a policy file with HMAC-SHA256 or Ed25519.

```
avakill sign [POLICY_FILE] [--key HEX] [--generate-key] [--ed25519]
```

| Argument/Option | Default | Description |
|-----------------|---------|-------------|
| `POLICY_FILE` | *(required unless `--generate-key`)* | Path to the policy file |
| `--key` | *(from env)* | Hex-encoded signing key |
| `--generate-key` | `false` | Generate a new HMAC key and print it |
| `--ed25519` | `false` | Use Ed25519 signing (requires PyNaCl) |

Creates a `.sig` sidecar file alongside the policy. Uses `AVAKILL_POLICY_KEY` for HMAC or `AVAKILL_SIGNING_KEY` for Ed25519 from environment.

**Examples:**

```bash
# Generate an HMAC key
avakill sign --generate-key

# Sign with HMAC (key from environment)
export AVAKILL_POLICY_KEY=<key-hex>
avakill sign avakill.yaml

# Sign with HMAC (key inline)
avakill sign avakill.yaml --key a1b2c3d4...

# Sign with Ed25519
export AVAKILL_SIGNING_KEY=<private-key-hex>
avakill sign --ed25519 avakill.yaml
```

---

## avakill verify

Verify a policy file's signature.

```
avakill verify POLICY_FILE [--key HEX] [--verbose]
```

| Argument/Option | Default | Description |
|-----------------|---------|-------------|
| `POLICY_FILE` | *(required)* | Path to the policy file |
| `--key` | *(from env)* | Hex-encoded signing/verify key |
| `--verbose`, `-v` | `false` | Show full file metadata (SHA-256, size, permissions) |

Auto-detects whether the `.sig` file contains an HMAC or Ed25519 signature. Uses `AVAKILL_POLICY_KEY` for HMAC or `AVAKILL_VERIFY_KEY` for Ed25519.

**Examples:**

```bash
# Verify (key from environment)
avakill verify avakill.yaml

# Verify with verbose metadata
avakill verify avakill.yaml -v

# Verify with explicit key
avakill verify avakill.yaml --key a1b2c3d4...
```

---

## avakill harden

Apply OS-level hardening to a policy file.

```
avakill harden [POLICY_FILE] [--chattr] [--schg] [--selinux] [--apparmor] [--seccomp] [-o PATH]
```

| Argument/Option | Default | Description |
|-----------------|---------|-------------|
| `POLICY_FILE` | `avakill.yaml` | Path to the policy file |
| `--chattr` | `false` | Set Linux immutable flag (`chattr +i`). Requires root. |
| `--schg` | `false` | Set macOS system immutable flag (`chflags schg`). Requires root. |
| `--selinux` | `false` | Output SELinux type enforcement template |
| `--apparmor` | `false` | Output AppArmor profile template |
| `--seccomp` | `false` | Output seccomp-bpf profile JSON |
| `--output`, `-o` | *(stdout)* | Write template output to file |

When no specific flag is given, auto-detects the platform and applies the appropriate immutable flag.

**Examples:**

```bash
# Auto-detect platform and set immutable flag
sudo avakill harden avakill.yaml

# Linux: set chattr +i
sudo avakill harden --chattr avakill.yaml

# macOS: set chflags schg
sudo avakill harden --schg avakill.yaml

# Generate SELinux template
avakill harden --selinux -o avakill.te avakill.yaml

# Generate seccomp profile for Docker
avakill harden --seccomp -o seccomp.json avakill.yaml
```

---

## avakill check-hardening

Report hardening status of a policy file.

```
avakill check-hardening [POLICY_FILE]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `POLICY_FILE` | `avakill.yaml` | Path to the policy file |

Shows immutable flag status, file permissions, owner/group, signing configuration, and signature validity.

**Example:**

```bash
avakill check-hardening avakill.yaml
```

---

## avakill schema

Export the AvaKill policy JSON Schema or generate an LLM prompt.

```
avakill schema [--format json|prompt] [--compact] [--tools TOOLS] [--use-case DESC] [-o PATH]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `json` | Output format: `json` for JSON Schema, `prompt` for LLM prompt |
| `--compact` | `false` | Minified JSON output (only with `--format=json`) |
| `--tools` | *(none)* | Comma-separated tool names to include in the prompt |
| `--use-case` | *(none)* | Description of your use case (e.g. `code assistant`) |
| `-o`, `--output` | *(stdout)* | Write output to a file |

**Examples:**

```bash
# Export JSON Schema
avakill schema

# Minified JSON for embedding
avakill schema --compact -o schema.json

# Generate LLM prompt
avakill schema --format=prompt

# Customized prompt with your tools
avakill schema --format=prompt --tools="execute_sql,shell_exec,file_write" --use-case="data pipeline"

# Save prompt to file
avakill schema --format=prompt -o prompt.txt
```

---

## avakill profile list

List available agent containment profiles.

```
avakill profile list [--verbose]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--verbose`, `-v` | `false` | Show profile descriptions |

Displays a table of built-in agent profiles with their hook support and MCP capabilities.

**Example:**

```bash
$ avakill profile list -v
       Agent Profiles
┌────────────┬───────┬─────┬──────────────────────┐
│ Name       │ Hooks │ MCP │ Description          │
├────────────┼───────┼─────┼──────────────────────┤
│ Claude Code│ yes   │ yes │ Anthropic CLI agent  │
│ Aider      │ no    │ no  │ AI pair programmer   │
│ OpenClaw   │ yes   │ yes │ Open-source agent    │
└────────────┴───────┴─────┴──────────────────────┘
```

---

## avakill profile show

Show details of an agent containment profile.

```
avakill profile show NAME
```

| Argument | Required | Description |
|----------|----------|-------------|
| `NAME` | Yes | Profile name (e.g. `openclaw`, `aider`, `claude-code`) |

Displays the full profile details including protection modes, detection paths, sandbox paths, network rules, and resource limits.

**Example:**

```bash
avakill profile show openclaw
```

---

## avakill compliance report

Generate a compliance assessment report.

```
avakill compliance report --framework FRAMEWORK --policy PATH [--format FORMAT] [--output FILE]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--framework` | *(required)* | Framework: `soc2`, `nist-ai-rmf`, `eu-ai-act`, `iso-42001`, or `all` |
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--format` | `table` | Output format: `table`, `json`, or `markdown` |
| `--output` | *(stdout)* | Write output to file |

**Examples:**

```bash
avakill compliance report --framework soc2 --policy avakill.yaml
avakill compliance report --framework all --policy avakill.yaml --format json --output compliance.json
```

---

## avakill compliance gaps

Show compliance gaps for the current configuration.

```
avakill compliance gaps [--policy PATH]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |

**Example:**

```bash
avakill compliance gaps --policy avakill.yaml
```

---

## avakill mcp-wrap

Wrap MCP server configs to route tool calls through AvaKill.

```
avakill mcp-wrap [--agent AGENT] [--policy PATH] [--daemon] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--agent` | `all` | Which agent to wrap: `claude-desktop`, `cursor`, `windsurf`, `cline`, `continue`, or `all` |
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--daemon` | `false` | Use daemon mode instead of embedded Guard |
| `--dry-run` | `false` | Show changes without writing |

Rewrites agent MCP configs so all stdio-transport tool calls pass through `avakill mcp-proxy`. Creates a backup of the original config. Skips servers that are already wrapped or use non-stdio transports.

**Examples:**

```bash
# Wrap all detected agents
avakill mcp-wrap

# Wrap a specific agent with custom policy
avakill mcp-wrap --agent claude-desktop --policy hardened.yaml

# Use daemon mode for evaluation
avakill mcp-wrap --agent all --daemon

# Preview changes without writing
avakill mcp-wrap --dry-run
```

---

## avakill mcp-unwrap

Restore original MCP server configs (undo mcp-wrap).

```
avakill mcp-unwrap [--agent AGENT]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--agent` | `all` | Which agent to unwrap: `claude-desktop`, `cursor`, `windsurf`, `cline`, `continue`, or `all` |

Reverses the wrapping done by `mcp-wrap`, restoring the original server commands. Creates a backup before writing.

**Examples:**

```bash
# Unwrap all agents
avakill mcp-unwrap

# Unwrap a specific agent
avakill mcp-unwrap --agent claude-desktop
```

---

## avakill enforce landlock

Apply Landlock filesystem restrictions (Linux 5.13+).

> **Future release** — code-complete but not yet tested in production. May change before general availability.

```
avakill enforce landlock --policy PATH [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--dry-run` | `false` | Show what would be restricted without applying |

Translates deny rules into Landlock filesystem access restrictions. **Applying is irreversible for the current process.** Requires Linux 5.13+, unprivileged.

**Examples:**

```bash
avakill enforce landlock --policy avakill.yaml --dry-run
avakill enforce landlock --policy avakill.yaml
```

---

## avakill enforce sandbox

Generate a macOS sandbox-exec SBPL profile.

> **Future release** — code-complete but not yet tested in production. May change before general availability.

```
avakill enforce sandbox --policy PATH [--output PATH] [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--output`, `-o` | *(none)* | Output path for the SBPL profile (required when not using `--dry-run`) |
| `--dry-run` | `false` | Print generated profile to stdout without writing |

macOS only.

**Examples:**

```bash
avakill enforce sandbox --policy avakill.yaml --output avakill.sb
sandbox-exec -f avakill.sb python my_agent.py

# Preview without writing
avakill enforce sandbox --policy avakill.yaml --dry-run
```

---

## avakill enforce windows

Apply Windows process restrictions.

> **Future release** — code-complete but not yet tested in production. May change before general availability.

```
avakill enforce windows --policy PATH [--dry-run]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--dry-run` | `false` | Show restrictions without applying |

Creates a Job Object with child-process limits and removes dangerous token privileges (SeRestorePrivilege, SeBackupPrivilege, etc.). **Privilege removal is irreversible for the process lifetime.** Requires Windows.

**Examples:**

```bash
# Preview restrictions
avakill enforce windows --policy avakill.yaml --dry-run

# Apply restrictions
avakill enforce windows --policy avakill.yaml
```

---

## avakill enforce tetragon

Generate a Cilium Tetragon TracingPolicy.

> **Future release** — code-complete but not yet tested in production. May change before general availability.

```
avakill enforce tetragon --policy PATH --output PATH
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--output` | *(required)* | Output path for the TracingPolicy YAML |

**Examples:**

```bash
avakill enforce tetragon --policy avakill.yaml --output tetragon-policy.yaml
kubectl apply -f tetragon-policy.yaml
```

---

## avakill launch

Launch a process inside an OS-level sandbox.

> **Future release** — code-complete but not yet tested in production. May change before general availability. Depends on untested enforce backends.

```
avakill launch [--policy PATH] [--agent NAME] [--pty|--no-pty] [--dry-run] [--timeout N] [--keep-profile] -- COMMAND...
```

| Option | Default | Description |
|--------|---------|-------------|
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--agent` | *(none)* | Agent profile name (e.g. `openclaw`, `aider`) |
| `--pty/--no-pty` | `--no-pty` | Allocate PTY for interactive agents |
| `--dry-run` | `false` | Show sandbox restrictions without launching |
| `--timeout` | *(none)* | Kill child process after N seconds |
| `--keep-profile` | `false` | Save the generated sandbox profile for inspection |
| `COMMAND` | *(from profile)* | Command to run (everything after `--`) |

The command to run can be specified after `--` or pulled from the agent profile's default command. If `--agent` is specified, the profile's sandbox configuration is used when the policy has no `sandbox:` section.

**Exit codes:**

| Code | Meaning |
|------|---------|
| *(child's code)* | Propagated from the child process |
| `126` | Sandbox setup failed |

**Examples:**

```bash
# Launch with explicit command
avakill launch --policy hardened.yaml -- openclaw start

# Launch using agent profile defaults
avakill launch --agent openclaw

# Launch with profile and custom command
avakill launch --agent aider -- aider --model gpt-4

# Preview sandbox restrictions
avakill launch --dry-run --agent openclaw

# Set a timeout
avakill launch --agent openclaw --timeout 3600

# Keep generated sandbox profile for inspection
avakill launch --agent openclaw --keep-profile
```

---

## avakill mcp-proxy

Start the MCP transparent proxy.

> **Future release** — code-complete but not yet tested in production. May change before general availability. Not yet tested with a real MCP server.

```
avakill mcp-proxy --upstream-cmd CMD [--upstream-args ARGS] [--policy PATH] [--log-db PATH] [--daemon SOCKET] [--agent NAME]
avakill mcp-proxy --upstream-url URL [--listen-port PORT] [--policy PATH] [--log-db PATH] [--daemon SOCKET] [--agent NAME]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--upstream-cmd` | *(none)* | Stdio: command to run the upstream MCP server |
| `--upstream-args` | `""` | Stdio: arguments for the upstream command (space-separated) |
| `--upstream-url` | *(none)* | HTTP: URL of the upstream MCP server |
| `--listen-port` | `5100` | HTTP: local port to listen on |
| `--policy` | `avakill.yaml` | Path to the policy file |
| `--log-db` | *(none)* | Path to the audit database (omit to disable logging) |
| `--daemon` | *(none)* | Evaluate via daemon socket instead of embedded Guard |
| `--agent` | `mcp` | Agent name for tool normalization |

Sits between an MCP client and an upstream MCP server, intercepting `tools/call` requests and evaluating them against the policy. Supports two transport modes: stdio (with `--upstream-cmd`) and HTTP (with `--upstream-url`). See the [MCP Proxy Guide](internal/mcp-proxy.md) for detailed setup.

**Examples:**

```bash
# Stdio proxy
avakill mcp-proxy --upstream-cmd python --upstream-args "server.py"

# With custom policy and logging
avakill mcp-proxy \
    --upstream-cmd node \
    --upstream-args "dist/server.js" \
    --policy policies/mcp.yaml \
    --log-db /var/log/avakill/mcp-audit.db

# HTTP proxy
avakill mcp-proxy --upstream-url http://localhost:8080 --listen-port 5100

# Evaluate via daemon instead of embedded Guard
avakill mcp-proxy --upstream-cmd python --upstream-args "server.py" --daemon /tmp/avakill.sock
```

---

## avakill metrics

Start a Prometheus metrics HTTP server.

> **Future release** — code-complete but not yet tested in production. May change before general availability. Requires the `[metrics]` extra: `pip install avakill[metrics]`.

```
avakill metrics [--port PORT] [--host HOST]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | `9090` | HTTP port for `/metrics` endpoint |
| `--host` | `0.0.0.0` | Bind address |

Exposes AvaKill metrics at `http://<host>:<port>/metrics` for Prometheus scraping.

**Examples:**

```bash
# Default port
avakill metrics

# Custom port and bind to localhost only
avakill metrics --port 9100 --host 127.0.0.1
```

---

## Further Reading

- **[Getting Started](getting-started.md)** — walkthrough using the CLI
- **[Policy Reference](policy-reference.md)** — full YAML schema
- **[Security Hardening](internal/security-hardening.md)** — signing and hardening workflows
- **[Deployment](internal/deployment.md)** — production deployment patterns
- **[Framework Integrations](internal/framework-integrations.md)** — native hooks and SDK wrappers
