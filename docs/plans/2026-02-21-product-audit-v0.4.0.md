# AvaKill Product Audit — v0.4.0

## Local Install for E2E Testing

```bash
cd /Users/ablecoffee/avakill
pipx install . --force
```

Re-run with `--force` after any code changes to pick them up.

---

## Purpose

Full command-by-command audit of what's production-ready vs. scaffolded. This doc is the source of truth before we plan any E2E testing or decide what ships in v1.

**Legend:**
- **BATTLE-TESTED** — Has been used by a human in real workflows, bugs found and fixed
- **PRODUCTION** — Code is complete, handles errors, has tests, but never human-tested E2E
- **FUNCTIONAL** — Works but has rough edges or missing error handling
- **SCAFFOLD** — Structure exists, code compiles, tests pass, but logic is thin or generates templates without real enforcement

---

## Tier 1: Core (what users need on day 1)

### `avakill quickstart`
- **⏳ REVISIT LAST** — integration layer; audit underlying pieces first
- **File**: `cli/quickstart_cmd.py` (182 lines)
- **Status**: PRODUCTION
- **What it does**: Guided setup — detects agents, selects protection level, scans for sensitive files, generates policy YAML, installs hooks
- **Dependencies**: `hooks.installer.detect_agents()`, `hooks.installer.install_hook()`, policy templates
- **Concerns**: Never tested by a real first-time user. Interactive prompts assume terminal. No fallback if agent detection fails. Doesn't guide daemon startup.
- **E2E test**: Fresh machine, `pipx install avakill`, `avakill quickstart`, verify policy + hooks installed, agent actually blocked on first dangerous call
- **v1?**: YES — this is the front door

### `avakill init`
- **⏳ REVISIT LAST** — overlaps with quickstart; decide whether to merge or differentiate
- **File**: `cli/init_cmd.py` (295 lines)
- **Status**: PRODUCTION
- **What it does**: Creates a new policy file with template selection, framework detection, mode selection
- **Dependencies**: Policy templates, framework detection via dependency file scanning
- **Concerns**: Overlaps with `quickstart`. Framework detection is basic (keyword search in requirements.txt). Never tested by a real user.
- **E2E test**: Run in empty project, Python project, Node project — verify generated policy is valid
- **v1?**: MAYBE — overlaps with quickstart. Could confuse users to have both `init` and `quickstart`.

### `avakill hook install / uninstall / list`
- **File**: `cli/hook_cmd.py`
- **Status**: BATTLE-TESTED
- **What it does**: Registers/removes avakill hooks in agent configs (Claude Code, Gemini, Cursor, Windsurf, OpenAI Codex)
- **Dependencies**: `hooks.installer` module
- **Evidence**: You've installed/uninstalled hooks in real Claude Code sessions. Hook blocking is working right now.
- **E2E test**: Already tested live. Needs testing on other agents (Gemini, Cursor, Windsurf, Codex).
- **v1?**: YES — critical path

### `avakill validate` ✅
- **File**: `cli/validate_cmd.py` (209 lines)
- **Status**: BATTLE-TESTED
- **What it does**: Validates YAML syntax, schema, shows rules table, detects shadowed rules
- **Dependencies**: `PolicyEngine.from_dict()`, `ConfigError`
- **Concerns**: Likely used during development but needs explicit E2E verification
- **E2E test**: Feed it valid, invalid, and edge-case YAML files, verify output
- **v1?**: YES
- **Example use cases**:
  ```bash
  # Check your policy is valid after editing
  avakill validate

  # Validate a specific policy file
  avakill validate /path/to/custom-policy.yaml

  # CI gate — exits 1 on invalid policy, 0 on valid
  avakill validate avakill.yaml || echo "Policy is broken!"
  ```

### `avakill evaluate` ✅
- **File**: `cli/evaluate_cmd.py` (225 lines)
- **Status**: BATTLE-TESTED
- **What it does**: Evaluates a tool call against policy. Dual-mode: daemon or standalone. Reads JSON from stdin.
- **Evidence**: This is what the hook binaries call. Working in production right now.
- **E2E test**: Already tested live via hooks
- **v1?**: YES — the engine
- **Example use cases**:
  ```bash
  # Test if a specific tool call would be blocked
  echo '{"tool": "Bash", "args": {"cmd": "rm -rf /"}}' | avakill evaluate --policy avakill.yaml

  # Get machine-readable JSON output for scripting
  echo '{"tool": "Write", "args": {"path": "/etc/passwd"}}' | avakill evaluate --policy avakill.yaml --json

  # Test rate limiting — simulate 50 rapid calls
  echo '{"tool": "Bash", "args": {"cmd": "curl api.example.com"}}' | avakill evaluate --policy avakill.yaml --simulate-burst 50

  # Evaluate via running daemon (no --policy needed)
  echo '{"tool": "Bash", "args": {"cmd": "ls"}}' | avakill evaluate
  ```

### `avakill fix` ✅
- **File**: `cli/fix_cmd.py` (159 lines)
- **Status**: BATTLE-TESTED
- **What it does**: Queries audit DB, maps denials to recovery hints, renders rich cards with steps, commands, and YAML snippets
- **Dependencies**: `SQLiteLogger`, `recovery_hint_for()`
- **E2E test**: Triggered denial via daemon, verified fix card renders with actionable guidance
- **v1?**: YES — recovery UX
- **Example use cases**:
  ```bash
  # See why your last tool call was blocked and how to fix it
  avakill fix --db avakill_audit.db

  # See all recent denials (up to 20)
  avakill fix --all --db avakill_audit.db

  # Machine-readable output for dashboards or scripts
  avakill fix --json --db avakill_audit.db
  ```

### Hook Binaries (`avakill-hook-claude-code`, etc.)
- **Status**: BATTLE-TESTED (claude-code), PRODUCTION (others)
- **What they do**: Pre-tool-use hook scripts that call `avakill evaluate`
- **Evidence**: Claude Code hook is blocking real attacks right now
- **E2E test**: Test each hook binary with its respective agent
- **v1?**: YES

---

## Tier 2: Operations (day 2+ features)

### `avakill logs tail` ✅
- **File**: `cli/logs_cmd.py` (233 lines)
- **Status**: BATTLE-TESTED
- **What it does**: Query/display audit logs from SQLite. Supports filtering, time ranges, JSON export, live tail
- **Dependencies**: `SQLiteLogger`
- **E2E test**: All cases tested live — query, filters, JSON, live tail with real-time event streaming
- **v1?**: YES — observability
- **Example use cases**:
  ```bash
  # View recent audit events
  avakill logs --db avakill_audit.db

  # Show only denied events
  avakill logs --db avakill_audit.db --denied-only

  # Filter by tool name
  avakill logs --db avakill_audit.db --tool Bash

  # Filter by time — events from last 5 minutes
  avakill logs --db avakill_audit.db --since 5m

  # JSON output for scripting (limit to 2 entries)
  avakill logs --db avakill_audit.db --json --limit 2

  # Live tail — watch events stream in real-time (Ctrl+C to stop)
  avakill logs --db avakill_audit.db tail

  # Combine filters with tail — watch only denials live
  avakill logs --db avakill_audit.db --denied-only tail
  ```

### `avakill dashboard` ✅
- **File**: `cli/dashboard_cmd.py` (350 lines)
- **Status**: BATTLE-TESTED
- **What it does**: Rich TUI dashboard with live event streaming, stats, keyboard input
- **Dependencies**: `SQLiteLogger`, `EventBus`, `Guard`, terminal raw mode
- **E2E test**: Launched live, verified real-time event streaming, stats updating, denied bar chart, keyboard shortcuts (q/r/c). Fixed 'c' clear and 'r' reload during audit.
- **v1?**: NICE-TO-HAVE — impressive demo but not essential
- **Example use cases**:
  ```bash
  # Launch dashboard (requires daemon running with --log-db)
  avakill dashboard --db avakill_audit.db

  # Launch with policy monitoring — 'r' reloads, --watch auto-reloads on file change
  avakill dashboard --db avakill_audit.db --policy avakill.yaml --watch

  # Custom refresh rate (default 0.5s)
  avakill dashboard --db avakill_audit.db --refresh 1.0

  # Keyboard shortcuts while dashboard is running:
  #   q — quit
  #   r — reload policy (shows [Policy reloaded] in footer)
  #   c — clear event list (shows [Cleared], new events still appear)
  ```

### `avakill daemon start / stop / status` ✅
- **File**: `cli/daemon_cmd.py`
- **Status**: BATTLE-TESTED
- **What it does**: Manages the persistent evaluation daemon (Unix domain socket)
- **Dependencies**: `daemon.server`, `daemon.transport`
- **E2E test**: Full lifecycle tested — background start, status check, evaluate through daemon (allow + deny), double-start prevention, stop, stop-when-not-running, missing policy error
- **v1?**: YES for performance — but the hookless mode works without it
- **Example use cases**:
  ```bash
  # Start daemon in background
  avakill daemon start --policy avakill.yaml

  # Start with audit logging
  avakill daemon start --policy avakill.yaml --log-db avakill_audit.db

  # Start in foreground (for debugging / development)
  avakill daemon start --foreground --policy avakill.yaml

  # Check if daemon is running
  avakill daemon status

  # Evaluate tool calls through the daemon (no --policy needed)
  echo '{"tool": "Bash", "args": {"command": "ls"}}' | avakill evaluate

  # Stop the daemon
  avakill daemon stop
  ```

### `avakill review` ✅
- **File**: `cli/review_cmd.py` (99 lines)
- **Status**: BATTLE-TESTED
- **What it does**: Pretty-prints a proposed policy file for human review before approval. Shows syntax-highlighted YAML, rules table, summary, and next steps.
- **E2E test**: Tested with valid proposed policy, invalid policy (clean error formatting), missing file, and active policy review
- **v1?**: YES — part of the propose/review/approve workflow
- **Example use cases**:
  ```bash
  # Review a proposed policy before activating
  avakill review avakill.proposed.yaml

  # Review your active policy
  avakill review avakill.yaml

  # Workflow: create proposed, review, then approve
  # 1. Agent writes changes to a .proposed.yaml file
  # 2. Human reviews:
  avakill review avakill.proposed.yaml
  # 3. Human activates:
  avakill approve avakill.proposed.yaml
  ```

### `avakill approve`
- **File**: `cli/approve_cmd.py` (104 lines)
- **Status**: FUNCTIONAL
- **What it does**: Validates proposed policy, prompts user, copies to active, auto-signs if key available
- **Concerns**: No atomic write (could fail mid-copy). No backup of existing policy. Auto-sign silently skips on error.
- **E2E test**: Create proposed, approve it, verify active policy updated, verify old policy wasn't lost
- **v1?**: YES — part of the propose/review/approve workflow

### `avakill approvals list / grant / reject`
- **File**: `cli/approval_cmd.py`
- **Status**: FUNCTIONAL
- **What it does**: Manages pending approval requests (for `require_approval` policy action)
- **Dependencies**: `approval.ApprovalStore` (SQLite)
- **Concerns**: Async pattern is rough. Has this workflow ever been triggered end-to-end?
- **E2E test**: Set a policy rule to `require_approval`, trigger a tool call, verify it shows in `approvals list`, grant it, verify tool call proceeds
- **v1?**: MAYBE — `require_approval` is a powerful feature but adds complexity

---

## Tier 3: Security Hardening

### `avakill sign`
- **File**: `cli/sign_cmd.py` (125 lines)
- **Status**: PRODUCTION
- **What it does**: Signs policy file with HMAC-SHA256 or Ed25519
- **Dependencies**: `integrity.PolicyIntegrity`, optional PyNaCl for Ed25519
- **Concerns**: Crypto code is sensitive. Has the HMAC path been tested? Has the Ed25519 path been tested with real keys?
- **E2E test**: `avakill keygen`, `avakill sign --ed25519`, `avakill verify`, round-trip
- **v1?**: NICE-TO-HAVE — important for enterprise but most users won't sign policies

### `avakill verify`
- **File**: `cli/verify_cmd.py` (89 lines)
- **Status**: PRODUCTION
- **What it does**: Verifies policy signature, auto-detects algorithm
- **E2E test**: Sign then verify, tamper with file, verify rejection
- **v1?**: NICE-TO-HAVE — pairs with sign

### `avakill keygen`
- **File**: `cli/keygen_cmd.py` (40 lines)
- **Status**: FUNCTIONAL
- **What it does**: Generates Ed25519 keypair, prints to stdout
- **Concerns**: Minimal — just calls PyNaCl. No key storage. User must manage env vars.
- **v1?**: NICE-TO-HAVE

### `avakill harden`
- **File**: `cli/harden_cmd.py` (154 lines)
- **Status**: PRODUCTION
- **What it does**: Sets immutable flags (chattr/chflags), outputs hardening templates (SELinux, AppArmor, seccomp)
- **Concerns**: Requires root on Linux. Has this been run on macOS? On Linux?
- **E2E test**: Run on macOS, verify immutable flag set, verify policy file can't be deleted
- **v1?**: LATER — advanced hardening

### `avakill check-hardening`
- **File**: `cli/check_hardening_cmd.py` (114 lines)
- **Status**: PRODUCTION
- **What it does**: Reports hardening status (immutable, permissions, signing, C hooks)
- **E2E test**: Run before and after `avakill harden`, verify status changes
- **v1?**: LATER

---

## Tier 4: Advanced / Enterprise

### `avakill enforce landlock`
- **File**: `cli/enforce_cmd.py` + `enforcement/landlock.py`
- **Status**: PRODUCTION (code complete, never human-tested)
- **What it does**: Applies Linux Landlock LSM restrictions via raw ctypes syscalls
- **Concerns**: **HIGH RISK** — Uses `ctypes.CDLL("libc.so.6")` with raw syscall numbers. One wrong flag crashes the process or silently fails. Requires Linux 5.13+. Has this EVER been run on a real Linux box?
- **E2E test**: Needs a Linux VM/container. Apply landlock, verify file writes blocked, verify reads allowed.
- **v1?**: NO — requires Linux, untested, high risk

### `avakill enforce sandbox`
- **File**: `cli/enforce_cmd.py` + `enforcement/sandbox_exec.py`
- **Status**: PRODUCTION (code complete, never human-tested)
- **What it does**: Generates macOS sandbox-exec SBPL profiles
- **Concerns**: SBPL is Apple-internal format with no public documentation. Has anyone run a process inside a generated sandbox and verified enforcement?
- **E2E test**: Generate profile, launch sandboxed process, verify writes blocked
- **v1?**: NO — undocumented Apple API, untested

### `avakill enforce windows`
- **File**: `cli/enforce_cmd.py` + `enforcement/windows.py`
- **Status**: PRODUCTION (code complete, never tested on Windows)
- **What it does**: Job Objects + privilege removal via ctypes
- **Concerns**: Do you even have a Windows machine to test this?
- **E2E test**: Needs Windows. Create job object, verify privilege removal, verify process limits.
- **v1?**: NO

### `avakill enforce tetragon`
- **File**: `cli/enforce_cmd.py` + `enforcement/tetragon.py`
- **Status**: PRODUCTION (generates YAML only)
- **What it does**: Generates Cilium Tetragon TracingPolicy YAML
- **Concerns**: Output-only — doesn't apply anything. Needs a Kubernetes cluster with Cilium to verify the YAML works.
- **E2E test**: Needs k8s cluster with Tetragon
- **v1?**: NO — enterprise/k8s only

### `avakill launch`
- **File**: `cli/launch_cmd.py` (168 lines)
- **Status**: SCAFFOLD (by our standards)
- **What it does**: Loads agent profile, resolves sandbox config, launches process in OS sandbox with PTY relay
- **Concerns**: Complex integration of profiles + sandbox backends + PTY. Each backend (landlock, sandbox-exec, windows) is untested. Profile YAML files are thin.
- **E2E test**: `avakill launch --profile openclaw -- python agent.py`, verify sandbox applied
- **v1?**: NO — depends on untested backends

### `avakill mcp-proxy`
- **File**: `cli/mcp_proxy_cmd.py` + `mcp/proxy.py` (23KB)
- **Status**: PRODUCTION (code is substantial, never tested with real MCP server)
- **What it does**: Transparent MCP proxy — intercepts tools/call JSON-RPC messages, evaluates against policy
- **Concerns**: MCP protocol is evolving. Has this been tested with a real MCP server (e.g., Claude Desktop connecting to a filesystem MCP server through the proxy)?
- **E2E test**: Configure MCP server, route through proxy, verify tool calls intercepted and policy applied
- **v1?**: MAYBE — high value if it works, but untested

### `avakill mcp-wrap / mcp-unwrap`
- **File**: `cli/mcp_wrap_cmd.py` + `mcp/wrapper.py`
- **Status**: PRODUCTION
- **What it does**: Rewrites MCP server configs to route through avakill proxy
- **Concerns**: Modifies real agent configs (Claude Desktop, Cursor). One wrong JSON write breaks the agent.
- **E2E test**: Wrap a config, verify original backed up, unwrap, verify restored
- **v1?**: MAYBE — pairs with mcp-proxy

### `avakill compliance report / gaps`
- **File**: `cli/compliance_cmd.py` + `compliance/*`
- **Status**: PRODUCTION
- **What it does**: Assesses policy against SOC 2, NIST AI RMF, EU AI Act, ISO 42001
- **Concerns**: Is the output actually useful to a compliance officer? Are the control mappings accurate?
- **E2E test**: Run against a real policy, have someone with compliance knowledge review output
- **v1?**: NO — enterprise feature, needs domain expert review

### `avakill profile list / show`
- **File**: `cli/profile_cmd.py` + `profiles/*`
- **Status**: PRODUCTION
- **What it does**: Lists/shows agent containment profiles (openclaw, cline, aider, swe-agent, continue)
- **Concerns**: Profiles are YAML files with metadata. Are the sandbox configs in them accurate for each agent?
- **E2E test**: `avakill profile list`, `avakill profile show openclaw`, verify output makes sense
- **v1?**: MAYBE — useful for `launch` command but `launch` itself isn't v1

### `avakill metrics`
- **File**: `cli/metrics_cmd.py`
- **Status**: PRODUCTION
- **What it does**: Starts Prometheus metrics HTTP server
- **Dependencies**: Optional `prometheus-client` package
- **E2E test**: Start server, trigger evaluations, scrape /metrics endpoint
- **v1?**: NO — enterprise/observability

### `avakill schema`
- **File**: `cli/schema_cmd.py`
- **Status**: PRODUCTION
- **What it does**: Exports JSON Schema for policy files, generates LLM prompts
- **E2E test**: Export schema, validate a policy against it
- **v1?**: NICE-TO-HAVE

### `avakill guide`
- **File**: `cli/guide_cmd.py` (543+ lines)
- **Status**: PRODUCTION
- **What it does**: Interactive wizard for protection modes and policy creation
- **Concerns**: Large interactive flow. Never tested by a real user.
- **E2E test**: Run through each wizard path, verify generated config is valid
- **v1?**: MAYBE — overlaps with quickstart

---

## Core Modules (non-CLI)

| Module | Status | Notes |
|--------|--------|-------|
| `core/engine.py` (Guard) | BATTLE-TESTED | The heart of everything. Working in production. |
| `core/self_protection.py` | BATTLE-TESTED | Just fixed 9 bypasses, verified live |
| `core/models.py` | BATTLE-TESTED | Pydantic models, used everywhere |
| `core/shell_analysis.py` | PRODUCTION | Regex-based metachar detection, tested via shell_safe |
| `core/cascade.py` | PRODUCTION | Multi-level policy discovery + merge. 2 pre-existing test failures. |
| `core/normalization.py` | PRODUCTION | Agent-specific tool name mappings |
| `core/approval.py` | PRODUCTION | SQLite-backed approval store |
| `core/recovery.py` | PRODUCTION | Denial → recovery hint mapping |
| `core/integrity.py` | PRODUCTION | HMAC + Ed25519 policy signing |
| `core/watcher.py` | PRODUCTION | File watching with watchfiles + polling fallback |
| `daemon/server.py` | PRODUCTION | Async Unix socket server |
| `daemon/client.py` | PRODUCTION | Sync client, fail-closed |
| `daemon/transport.py` | PRODUCTION | Unix socket + TCP |
| `hooks/installer.py` | BATTLE-TESTED | Agent detection + hook install |
| `hooks/claude_code.py` | BATTLE-TESTED | Pre-tool-use hook adapter |
| `hooks/gemini_cli.py` | PRODUCTION | Untested with real Gemini CLI |
| `hooks/cursor.py` | PRODUCTION | Untested with real Cursor |
| `hooks/windsurf.py` | PRODUCTION | Untested with real Windsurf |
| `hooks/openai_codex.py` | PRODUCTION | Untested with real OpenAI Codex |
| `enforcement/landlock.py` | PRODUCTION | Raw ctypes, never run on real Linux |
| `enforcement/sandbox_exec.py` | PRODUCTION | SBPL generation, never run on real macOS sandbox |
| `enforcement/tetragon.py` | PRODUCTION | YAML generation only |
| `enforcement/windows.py` | PRODUCTION | Never run on Windows |
| `compliance/*` | PRODUCTION | Framework mappings, untested by domain expert |
| `mcp/proxy.py` | PRODUCTION | 23KB, never tested with real MCP server |
| `mcp/config.py` | PRODUCTION | Config discovery + parsing |
| `mcp/wrapper.py` | PRODUCTION | Config wrapping + backup |
| `profiles/*` | PRODUCTION | YAML profiles for agents |
| `launcher/*` | PRODUCTION | Process launcher + PTY relay |

---

## Proposed v1 Surface Area

### Ship (must work flawlessly)
1. `avakill quickstart`
2. `avakill hook install / uninstall / list`
3. `avakill validate`
4. `avakill evaluate`
5. `avakill fix`
6. `avakill logs tail`
7. `avakill review`
8. `avakill approve`
9. `avakill daemon start / stop / status`
10. All `avakill-hook-*` binaries

### Ship but mark as advanced
11. `avakill init`
12. `avakill sign / verify / keygen`
13. `avakill harden / check-hardening`
14. `avakill schema`
15. `avakill guide`

### Defer or gate behind feature flag
16. `avakill enforce *` (landlock, sandbox, windows, tetragon)
17. `avakill launch`
18. `avakill mcp-proxy / mcp-wrap / mcp-unwrap`
19. `avakill compliance *`
20. `avakill metrics`
21. `avakill profile *`
22. `avakill approvals *`
23. `avakill dashboard`

---

## Open Questions

1. Should `init` and `quickstart` be merged into one command?
2. Should deferred commands be hidden from `--help` or just documented as experimental?
3. Do we need to test hook adapters for agents other than Claude Code before v1?
4. Is the daemon required for v1 or is hookless mode sufficient?
5. What does the v1 release look like — PyPI only? GitHub release? Landing page?

---

## Issues Found During Audit

### ISSUE-1: Default policy tool patterns don't match real agent tool names
- **Severity**: HIGH — the out-of-the-box policy silently fails to protect
- **Found during**: `avakill evaluate` E2E testing
- **Details**: The default policy rules use generic glob patterns like `shell_*`, `bash_*`, `command_*`, `database_*`, `sql_*`. But real agents send specific tool names that don't match these patterns:
  - Claude Code sends `Bash`, not `bash_exec` or `shell_run`
  - Claude Code sends `Write`, `Edit`, `Read`, not `file_write`, `file_edit`
  - Other agents have their own names (see `core/normalization.py`)
- **Impact**: A user who installs avakill, runs `avakill validate` (which says "Policy is valid"), and trusts the default policy is **not actually protected** by the deny rules. Every tool call falls through to the catch-all `log-everything` allow rule. Self-protection and the hook layer are doing the real work — the policy rules are decorative.
- **Fix needed**: Default policy templates must include the actual tool names each agent uses. Either:
  1. Use concrete names alongside globs: `tools: ["Bash", "shell_*", "bash_*", "command_*"]`
  2. Expand globs per-agent during `quickstart`/`init` based on detected agent
  3. Add a normalization step in the engine that maps real tool names to canonical names before matching (this exists in `core/normalization.py` but may not be wired into the default flow)
- **Blocked commands**: `quickstart`, `init`, and any command that generates default policy templates

### ISSUE-2: Agents can kill the daemon via `avakill daemon stop`
- **Severity**: HIGH — defeats the entire protection model
- **Found during**: `avakill daemon` E2E testing
- **Details**: An AI agent can run `avakill daemon stop` through a shell tool and kill the evaluation daemon. Self-protection currently blocks `pipx uninstall avakill`, policy file modification, hook config tampering, and source file edits — but it does not block `avakill daemon stop`. An agent that wants to bypass protection can simply stop the daemon, then operate unguarded.
- **Impact**: Any agent with shell access can disable avakill's daemon-based protection in one command. The hook-based path (which doesn't use the daemon) is unaffected, but users who rely on the daemon for centralized evaluation lose protection silently.
- **Fix needed**: Self-protection should detect and block `avakill daemon stop` (and variants like `kill <pid>` targeting the daemon PID, `pkill avakill`, etc.) in shell arguments. The same pattern used for uninstall detection should be extended to daemon shutdown commands.
- **Blocked commands**: None — this is a self-protection gap, not a CLI bug
