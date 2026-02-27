# Architecture

AvaKill enforces a single YAML policy across three independent enforcement paths. Each path works standalone — no daemon required. The daemon adds shared evaluation, audit logging, and visibility tooling.

```
avakill.yaml (one policy file)
    |
    ├── Hooks (Claude Code, Cursor, Windsurf, Gemini, Codex)
    |     → work standalone, evaluate in-process
    |
    ├── MCP Proxy (wraps MCP servers)
    |     → works standalone, evaluate in-process
    |
    ├── OS Sandbox (launch + profiles)
    |     → works standalone, OS-level enforcement
    |
    └── Daemon (optional)
          → shared evaluation, audit logging
          → hooks/proxy CAN talk to it if running
          → enables: logs, fix, tracking, approvals, metrics
```

## Hooks

Hooks intercept tool calls inside AI coding agents before execution. Each agent has a native hook adapter that translates between the agent's JSON format and AvaKill's evaluation protocol.

### How hooks work

1. Agent is about to execute a tool (e.g., `Bash` in Claude Code)
2. Agent calls the hook binary with tool call JSON on stdin
3. Hook adapter parses the agent's native format into an `EvaluateRequest`
4. Hook evaluates against policy (standalone or via daemon)
5. Hook returns allow/deny/approval in the agent's expected format

### Hook evaluation fallback chain

Each hook follows the same fallback chain:

1. **Self-protection** — always runs, blocks attempts to modify AvaKill's own config
2. **`AVAKILL_POLICY` env var** — standalone evaluation against the specified policy
3. **Running daemon** — delegate to daemon via Unix socket
4. **Auto-discover** — look for `avakill.yaml` in the current working directory
5. **`AVAKILL_FAIL_CLOSED`** — if set, deny all calls when no policy is found
6. **Fail-open** — allow with a warning if no policy is found

### Supported agents

| Agent | Hook binary | Tool format |
|-------|-------------|-------------|
| Claude Code | `avakill-hook-claude-code` | `PreToolUse` JSON with `tool_name`, `tool_input` |
| Gemini CLI | `avakill-hook-gemini-cli` | `run_shell_command`, `read_file`, etc. |
| Cursor | `avakill-hook-cursor` | `shell_command`, `read_file` |
| Windsurf | `avakill-hook-windsurf` | `run_command`, `write_code`, `read_code` |
| OpenAI Codex | `avakill-hook-openai-codex` | `shell`, `apply_patch`, `read_file` |

## MCP Proxy

The MCP proxy sits between an MCP client and an MCP server, intercepting `tools/call` JSON-RPC requests. Three components:

### mcp-proxy

A Python-based transparent proxy. Supports two modes:

- **Stdio mode** — spawns the upstream MCP server as a subprocess, relays stdio
- **HTTP mode** — connects to a remote MCP server over HTTP, exposes a local port

The proxy intercepts `tools/call` requests, evaluates them against policy, and either forwards or blocks the call.

### mcp-wrap

A config rewriter. Reads agent MCP configuration files (Claude Desktop, Cursor, etc.), replaces each server entry with `avakill-shim -- <original command>`, and writes back. This routes all MCP tool calls through AvaKill without changing the MCP server itself.

### avakill-shim

A compiled Go binary that acts as a lightweight MCP proxy. Designed for use in MCP config files where you need a single binary with no Python dependency. Supports `--policy` for standalone evaluation and `--socket` for daemon delegation.

## OS Sandbox

The OS sandbox restricts what a launched process can do at the operating system level. This is the strongest enforcement — it cannot be bypassed by the sandboxed process.

### How it works

1. `avakill launch` reads the `sandbox` section from your policy (or an agent profile)
2. Generates a platform-specific sandbox profile
3. Launches the target process inside the sandbox
4. The OS kernel enforces filesystem, network, and resource restrictions

### Platform backends

| Platform | Backend | Privileges |
|----------|---------|-----------|
| Linux 5.13+ | Landlock | Unprivileged — no root required |
| macOS | sandbox-exec with SBPL profiles | Standard user |
| Linux (advanced) | Tetragon eBPF | Requires root/CAP_BPF |
| Windows | AppContainer | Standard user |

### Agent profiles

Pre-built sandbox profiles ship for common agents:

- `openclaw` — high-risk agent with MCP support
- `cline` — VS Code extension agent
- `continue` — VS Code extension agent
- `swe-agent` — Princeton SWE-Agent
- `aider` — AI pair programming

Each profile defines allowed paths, network connections, and resource limits tuned for that agent.

## Daemon

The daemon is an optional persistent process that provides shared evaluation and centralized services.

### What the daemon adds

- **Shared evaluation** — hooks and proxy delegate to a single daemon instance instead of each loading the policy independently
- **Audit logging** — all decisions logged to a SQLite database
- **Rate limiting** — shared rate limit state across all hooks/proxy instances
- **Approval queue** — `require_approval` decisions queued for human review
- **Metrics** — Prometheus-compatible metrics endpoint
- **Cross-call correlation** — track related tool calls across sessions

### Protocol

The daemon communicates over Unix domain sockets (or TCP) using newline-delimited JSON:

```json
// Request (from hook/CLI)
{"version": 1, "agent": "claude-code", "event": "pre_tool_use",
 "tool": "shell_execute", "args": {"command": "ls"}}

// Response (from daemon)
{"decision": "allow", "reason": null, "policy": "safe-commands",
 "latency_ms": 0.3}
```

### Architecture

```
Hook/CLI  →  Unix Socket  →  DaemonServer
                                  ↓
                             PolicyEngine
                                  ↓
                             AuditLogger (SQLite)
                                  ↓
                             EventBus → Metrics, Notifications
```

## Core engine

### PolicyEngine

The `PolicyEngine` is the pure evaluation core. It takes a `PolicyConfig` and a `ToolCall`, iterates through rules in order, and returns the first matching `Decision`.

Key properties:
- **First-match-wins** — rules are evaluated top to bottom, first match returns
- **Sub-millisecond** — pure rule evaluation, no ML models, no network calls
- **Deterministic** — same input always produces the same output (modulo rate limits)

### Guard

`Guard` wraps `PolicyEngine` with additional features:
- Policy loading from file/string/dict
- Self-protection against config tampering
- Policy signature verification
- Audit event emission via `EventBus`
- Session tracking and correlation

### Shell analysis

The `is_shell_safe()` function performs AST-level analysis of shell commands to detect metacharacters, pipes, redirects, and subshells. This is more reliable than regex — it handles quoting, escaping, and nested structures.

### Content scanning

The content scanner detects secrets (AWS keys, GitHub PATs, Stripe keys, PEM keys, bearer tokens) and prompt injection patterns in tool call arguments. Used by the `content_scan` policy condition and by the MCP proxy for response scanning.
