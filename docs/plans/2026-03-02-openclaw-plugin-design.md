# AvaKill OpenClaw Plugin — Design Document

**Date:** 2026-03-02
**Status:** Approved
**Author:** ablecoffee + Claude

---

## Overview

`avakill-openclaw` is an OpenClaw plugin that enforces AvaKill policies inside OpenClaw's gateway process. It ships as an npm package, installs with one command, and uses the same YAML policy file that AvaKill uses everywhere else.

OpenClaw is a major AI agent platform with no production-grade security firewall. The existing tools (ClawBands, openclaw-shield, SecureClaw) are either non-functional (waiting on `before_tool_call` to ship in binary) or soft-enforcement only (LLM instructions). AvaKill will be the first complete, multi-layered security plugin for OpenClaw.

---

## Six Enforcement Layers

| Layer | Hook | Status | What It Does |
|---|---|---|---|
| **L1: Hard Block** | `before_tool_call` | Auto-activates when OpenClaw ships it | Blocks tool calls before execution |
| **L2: Guard Tool** | `api.registerTool()` | Works now | Registers `avakill_guard` tool. Agent calls it before risky ops |
| **L3: Output Scan** | `tool_result_persist` | Works now | Scans tool results for secrets, PII, prompt injection. Redacts before model sees them |
| **L4: Message Gate** | `message_sending` | Works now | Blocks outbound messages containing secrets or policy violations |
| **L5: Spawn Control** | `subagent_spawning` | Works now | Rate-limits and blocks unauthorized subagent spawns |
| **L6: Context Inject** | `agent:bootstrap` | Works now | Injects safety rules into every agent session context |

When L1 activates, L2 (guard tool) gracefully steps back. L1 takes over. Zero user action required.

---

## User Experience

### Install

```bash
# From OpenClaw CLI
openclaw plugins install avakill-openclaw

# Or from AvaKill CLI
avakill hook install --agent openclaw
```

### What happens on install

1. Plugin drops into `~/.openclaw/extensions/avakill-openclaw/`
2. Auto-discovers policy file in cwd, or `AVAKILL_POLICY` env var, or `~/.config/avakill/policy.yaml`
3. If no policy found, copies a sensible default starter policy
4. Enables itself in `~/.openclaw/openclaw.json` under `plugins.entries.avakill-openclaw`
5. Prints: "AvaKill active. 6 enforcement layers. Policy loaded (47 rules)"

### Block messages

**L1 (hard block, when available):**
```
AvaKill blocked: bash("rm -rf /")
   Rule: block-catastrophic-commands
   Reason: Catastrophic shell command blocked
   Recovery: avakill fix --last
```

**L2 (guard tool, today):**
```
Agent: Let me check if this operation is allowed...
[calls avakill_guard(tool="bash", args={"command": "rm -rf /"})]

AvaKill: DENIED by block-catastrophic-commands.
Catastrophic shell command blocked.
Run `avakill fix --last` for recovery steps.

Agent: That operation was blocked by security policy. Let me find a safer approach.
```

**L3 (output scan):**
```
[tool result redacted — 2 secrets detected, 1 AWS key, 1 GitHub PAT]
```

### Plugin config

```json
{
  "plugins": {
    "entries": {
      "avakill-openclaw": {
        "enabled": true,
        "config": {
          "policy": "./policy.yaml",
          "daemon": false,
          "audit": true,
          "guardTool": true,
          "contextInject": true
        }
      }
    }
  }
}
```

---

## Architecture

### Plugin structure

```
avakill-openclaw/
  openclaw.plugin.json      # manifest (id, configSchema)
  package.json              # npm metadata, "openclaw" key
  src/
    index.ts              # register(api) entry point
    evaluator.ts          # bridges to AvaKill policy engine
    layers/
      hard-block.ts     # L1: before_tool_call
      guard-tool.ts     # L2: avakill_guard tool registration
      output-scan.ts    # L3: tool_result_persist
      message-gate.ts   # L4: message_sending
      spawn-control.ts  # L5: subagent_spawning
      context-inject.ts # L6: agent:bootstrap
    policy.ts             # YAML policy loader + hot reload watcher
    audit.ts              # local audit log (JSONL)
    normalize.ts          # OpenClaw tool names to AvaKill canonical names
  bootstrap/
    AVAKILL_RULES.md      # safety rules injected into agent context (L6)
  docs/
    getting-started.md
    policy-guide.md
    troubleshooting.md
```

### Policy engine: Pure TypeScript

The core AvaKill policy evaluation logic is reimplemented in TypeScript to run in-process with zero external dependencies:

- Zero Python dependency
- Zero process spawn latency
- Sub-millisecond evaluation
- `openclaw plugins install avakill-openclaw` just works

### What the TypeScript engine implements

- YAML parsing via `js-yaml`, validated against schema
- First-match-wins rule evaluation (identical to Python PolicyEngine.evaluate())
- Tool glob matching via `minimatch` (identical semantics to Python fnmatch)
- Wildcard support for `"*"` and `"all"`
- `args_match`: AND across keys, OR within each key's list, case-insensitive substring
- `args_not_match`: inverse
- `shell_safe`: regex metachar detection (pipes, redirects, chaining, subshells, eval/source/xargs)
- `command_allowlist`: first-token exact match
- `rate_limit`: sliding window with Map and window eviction
- `enforcement` levels: hard / soft / advisory
- `default_action`: allow / deny fallback
- Environment variable substitution in YAML values
- Self-protection: hardcoded blocks on policy file modification, avakill uninstall, daemon shutdown

### What defers to daemon/Python (not in v1)

- `path_match` / `path_not_match` (symlink resolution, workspace sentinel)
- `content_scan` (secrets + prompt injection regex detection)
- Cross-call correlation (T4 session-level patterns)
- Policy signing/integrity (Ed25519/HMAC verification)

### Tool name normalization (OpenClaw to AvaKill canonical)

```
bash            -> shell_execute
exec            -> shell_execute
system.run      -> shell_execute
file_read       -> file_read
file_write      -> file_write
file_edit       -> file_edit
glob            -> file_list
grep            -> content_search
list_dir        -> file_list
fetch           -> web_fetch
web_search      -> web_search
browser_navigate -> web_fetch
spawn_agent     -> agent_spawn
subagent        -> agent_spawn
MCP tools (mcp__server__tool) pass through unchanged
```

### Data flow (L1 — hard block)

```
Agent wants to call bash("rm -rf /")
  -> OpenClaw fires before_tool_call
  -> avakill-openclaw receives {toolName, params}
  -> normalize("bash") -> "shell_execute"
  -> PolicyEngine.evaluate("shell_execute", params)
  -> first-match: "block-catastrophic-commands" -> DENY
  -> return {block: true, blockReason: "..."}
  -> OpenClaw halts tool execution
  -> audit.append({tool, args, decision, rule, timestamp})
```

### Data flow (L2 — guard tool, today)

```
Agent bootstrap includes AVAKILL_RULES.md:
  "Before running shell commands, file writes, or database queries,
   call avakill_guard to check if the operation is permitted."

Agent wants to run bash("rm -rf /")
  -> Agent calls avakill_guard({tool: "bash", args: {command: "rm -rf /"}})
  -> normalize + evaluate -> DENY
  -> Tool returns: "DENIED by block-catastrophic-commands. ..."
  -> Agent reads denial, adjusts approach
  -> audit.append(...)
```

### Hot reload

File watcher on the policy YAML. When the policy changes, the in-process engine reloads. No gateway restart needed.

### Audit log

JSONL at `~/.openclaw/avakill/audit.jsonl`. Each line:

```json
{
  "timestamp": "2026-03-02T22:30:00.000Z",
  "tool": "shell_execute",
  "args": {"command": "rm -rf /"},
  "decision": "deny",
  "rule": "block-catastrophic-commands",
  "layer": "L2",
  "latency_ms": 0.3,
  "agent_id": "main",
  "session_key": "abc123"
}
```

Optional: forward to AvaKill daemon if running (for unified audit across all agents).

### Test strategy

Every evaluation behavior has a mirror test against the Python engine. Feed identical policy + tool call into both, assert identical decisions. Two engines, one truth.

---

## Documentation

Three docs ship with the plugin, each targeting a specific audience:

### 1. getting-started.md — OpenClaw users who have never heard of AvaKill

- Zero jargon, zero assumed knowledge
- Working in 2 minutes
- Full starter policy inline
- "Verify it works" section with a concrete test

### 2. policy-guide.md — Users who want to customize rules

- How first-match-wins works
- Full OpenClaw tool name mapping table
- Common patterns as copy-paste YAML snippets
- Enforcement layers explained with examples
- Testing instructions

### 3. troubleshooting.md — When things go wrong

- Problem-first format
- Every common error with exact fix command
- "Agent ignores the guard tool" section
- "AvaKill blocks something it shouldn't" section

### Site updates

- New docs page: /docs/openclaw/
- Landing page: OpenClaw added to "Works With Everything" integration pills
- Rule catalog: OpenClaw-specific examples

---

## Distribution and Launch

### Package

- Name: `avakill-openclaw` on npm
- License: MIT (thin bridge; AGPL engine stays in Python)
- Repo: `log-bell/avakill-openclaw` (separate repo)

### Install paths

```bash
# Primary (OpenClaw users)
openclaw plugins install avakill-openclaw

# Secondary (AvaKill users)
avakill hook install --agent openclaw
# -> detects OpenClaw, runs openclaw plugins install avakill-openclaw
```

### AvaKill CLI changes

- `avakill setup`: when OpenClaw detected, offer plugin install
- `avakill hook install --agent openclaw`: wraps `openclaw plugins install`
- `avakill hook uninstall --agent openclaw`: wraps `openclaw plugins uninstall`

### Version strategy

- `1.0.0`: ships with L2-L6 (all working today)
- `1.1.0`: when OpenClaw ships `before_tool_call` in binary, L1 auto-activates
- CI runs policy engine parity tests against AvaKill's Python engine

### Launch sequence

1. Ship plugin to npm as `avakill-openclaw`
2. Update `avakill setup` to detect + offer install
3. Add OpenClaw to the landing page integrations
4. Add `/docs/openclaw/` to the docs site
5. Post on OpenClaw Discord + GitHub Discussions
6. Write blog post: "Six Layers of Defense for Your OpenClaw Agent"
7. PR to OpenClaw community plugins list

---

## Competitive Positioning

| Feature | AvaKill | ClawBands | openclaw-shield | SecureClaw |
|---|---|---|---|---|
| Hard block (before_tool_call) | Ready, auto-activates | Ready, not functional | Ready, not functional | No |
| Working enforcement today | Yes (L2-L6) | No | Partial (L2, L4 only) | Soft only |
| Policy format | YAML, glob patterns, conditions | JSON, regex | JSON, regex | LLM instructions |
| First-match-wins engine | Yes | No | No | No |
| Rate limiting | Yes (sliding window) | No | No | No |
| Shell analysis | Yes (metachar + allowlist) | No | No | No |
| Audit trail | JSONL + optional daemon SQLite | JSONL | None | None |
| Output scanning | Yes (secrets, PII) | No | Yes | No |
| Message gate | Yes | No | No | No |
| Spawn control | Yes | No | No | No |
| Compliance reports | SOC 2, NIST, EU AI Act, ISO 42001 | No | No | OWASP checks |
| Cross-agent policy | Same policy file everywhere | OpenClaw only | OpenClaw only | OpenClaw only |
