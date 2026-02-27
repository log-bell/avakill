<div align="center">

# AvaKill

### Open-source safety firewall for AI agents

[![PyPI version](https://img.shields.io/pypi/v/avakill?color=blue)](https://pypi.org/project/avakill/)
[![Python](https://img.shields.io/pypi/pyversions/avakill)](https://pypi.org/project/avakill/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/log-bell/avakill/ci.yml?branch=main&label=tests)](https://github.com/log-bell/avakill/actions)
![Tests](https://img.shields.io/badge/tests-2%2C108%20passing-brightgreen)
![Red Team](https://img.shields.io/badge/red%20team-63%2F63%20blocked-red)
[![GitHub stars](https://img.shields.io/github/stars/log-bell/avakill?style=social)](https://github.com/log-bell/avakill)

**One YAML policy. Three independent enforcement paths. Every agent protected.**

```bash
pipx install avakill && avakill setup
```

[Quickstart](#quickstart) · [How It Works](#how-it-works) · [Integrations](#integrations) · [Policy](#policy-configuration) · [CLI](#cli) · [Docs](https://avakill.com/docs/getting-started/) · [Contributing](CONTRIBUTING.md)

</div>

---

## The Problem

AI agents are shipping to production with **zero safety controls** on their tool calls. The results are predictable:

- **Replit's agent** dropped a production database and fabricated 4,000 fake user accounts to cover it up.
- **Google's Gemini CLI** wiped a user's entire D: drive — 8,000+ files, gone.
- **Amazon Q** terminated EC2 instances and deleted infrastructure during a debugging session.

These aren't edge cases. Research shows AI agents fail in **75% of real-world tasks**, and when they fail, they fail catastrophically — because nothing sits between the agent and its tools.

**AvaKill is that missing layer.** A firewall that intercepts every tool call, evaluates it against your safety policies, and kills dangerous operations before they execute. No ML models, no API calls, no latency — just fast, deterministic policy checks in <1ms.

## Quickstart

```bash
pipx install avakill
avakill setup
```

> **macOS note:** macOS 14+ blocks `pip install` at the system level (PEP 668). Use `pipx` or a virtualenv.

`avakill setup` walks you through an interactive flow that:

1. **Detects agents** across three enforcement paths (hooks, MCP proxy, OS sandbox)
2. **Creates a policy** from a catalog of 81 rules across 14 categories
3. **Installs hooks** for detected agents (Claude Code, Cursor, Windsurf, Gemini CLI, Codex)
4. **Wraps MCP servers** for MCP-capable agents (Claude Desktop, Cline, Continue)
5. **Shows sandbox commands** for agents that support OS-level containment
6. **Enables tracking** (optional) for audit logs and diagnostics

After setup, test it:

```bash
echo '{"tool": "Bash", "args": {"command": "rm -rf /"}}' | avakill evaluate --policy avakill.yaml
# deny: Matched rule 'block-catastrophic-shell'
```

Safe calls pass through. Destructive calls are killed before they execute.

### Optional framework extras

```bash
pip install "avakill[openai]"       # OpenAI function calling
pip install "avakill[anthropic]"    # Anthropic tool use
pip install "avakill[langchain]"    # LangChain / LangGraph
pip install "avakill[mcp]"          # MCP proxy
pip install "avakill[all]"          # Everything
```

## How It Works

AvaKill enforces a single YAML policy across three independent enforcement paths. Each path works standalone — no daemon required, no single point of failure.

```
avakill.yaml (one policy file)
    |
    ├── Hooks (Claude Code, Cursor, Windsurf, Gemini CLI, Codex)
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

<table>
<tr>
<td width="50%">

**One Policy File**<br>
`avakill.yaml` is the single source of truth. Deny-by-default, allow lists, rate limits, argument pattern matching, shell safety checks, path resolution, and content scanning.

</td>
<td width="50%">

**Native Agent Hooks**<br>
Drop-in hooks for Claude Code, Cursor, Windsurf, Gemini CLI, and Codex. One command to install. Works standalone — no daemon required.

</td>
</tr>
<tr>
<td>

**MCP Proxy**<br>
Wraps any MCP server with policy enforcement. Scans tool responses for secrets, PII, and prompt injection. Works standalone, evaluates in-process.

</td>
<td>

**OS Sandbox**<br>
Launch agents in OS-level sandboxes. Landlock on Linux, sandbox-exec on macOS, Tetragon for Kubernetes, AppContainer on Windows.

</td>
</tr>
<tr>
<td>

**Sub-Millisecond**<br>
Pure rule evaluation, no ML models. Adds <1ms overhead to tool calls that already take 500ms-5s. Three enforcement paths, zero bottlenecks.

</td>
<td>

**Optional Daemon**<br>
Shared evaluation, audit logging, and visibility tooling. Hooks and proxy can talk to it when running. Enables logs, tracking, approvals, and metrics.

</td>
</tr>
</table>

## Integrations

### Native Agent Hooks

Protect AI agents with zero code changes — just install the hook:

```bash
# Install hooks (works standalone — no daemon required)
avakill hook install --agent claude-code  # or cursor, windsurf, gemini-cli, openai-codex, all
avakill hook list
```

Hooks work standalone by default — each hook evaluates policies in-process. Policies use canonical tool names (`shell_execute`, `file_write`, `file_read`) so one policy works across all agents.

| Agent | Hook Status |
|---|---|
| Claude Code | Battle-tested |
| Cursor | Supported |
| Windsurf | Supported |
| Gemini CLI | Supported |
| OpenAI Codex | Supported |

### MCP Proxy

Wrap MCP servers to route all tool calls through AvaKill:

```bash
avakill mcp-wrap --agent claude-desktop   # or cursor, windsurf, cline, continue, all
avakill mcp-unwrap --agent all            # Restore original configs
```

Supported agents: Claude Desktop, Cursor, Windsurf, Cline, Continue.dev.

### OS Sandbox

Launch agents in OS-level sandboxes with pre-built profiles:

```bash
avakill profile list                    # See available profiles
avakill profile show aider              # See what a profile restricts
avakill launch --agent aider -- aider   # Launch with OS sandbox
```

Profiles ship for OpenClaw, Cline, Continue, SWE-Agent, and Aider.

### Python SDK

For programmatic integration, AvaKill's `Guard` is available as a Python API:

```python
from avakill import Guard, protect

guard = Guard(policy="avakill.yaml")

@protect(guard=guard, on_deny="return_none")  # or "raise" (default), "callback"
def execute_sql(query: str) -> str:
    return db.execute(query)
```

**Framework wrappers:**

```python
# OpenAI
from avakill import GuardedOpenAIClient
client = GuardedOpenAIClient(OpenAI(), policy="avakill.yaml")

# Anthropic
from avakill import GuardedAnthropicClient
client = GuardedAnthropicClient(Anthropic(), policy="avakill.yaml")

# LangChain / LangGraph
from avakill import AvaKillCallbackHandler
handler = AvaKillCallbackHandler(policy="avakill.yaml")
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
```

## Policy Configuration

Policies are YAML files. Rules are evaluated top-to-bottom — first match wins.

```yaml
version: "1.0"
default_action: deny

policies:
  # Allow safe shell with allowlist + metacharacter protection
  - name: "allow-safe-shell"
    tools: ["shell_execute", "Bash", "run_shell_command", "run_command",
            "shell", "local_shell", "exec_command"]
    action: allow
    conditions:
      shell_safe: true
      command_allowlist: [echo, ls, cat, pwd, git, python, pip, npm, node, make]

  # Block destructive SQL
  - name: "block-destructive-sql"
    tools: ["execute_sql", "database_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
    message: "Destructive SQL blocked. Use a manual migration."

  # Block writes to system directories
  - name: "block-system-writes"
    tools: ["file_write", "file_edit", "Write", "Edit"]
    action: deny
    conditions:
      path_match:
        file_path: ["/etc/", "/usr/", "/bin/", "/sbin/"]

  # Scan for secrets in tool arguments
  - name: "block-secret-leaks"
    tools: ["*"]
    action: deny
    conditions:
      content_scan: true

  # Rate limit API calls
  - name: "rate-limit-search"
    tools: ["web_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "60s"

  # Require human approval for file writes
  - name: "approve-writes"
    tools: ["file_write"]
    action: require_approval
```

**Policy features:**
- **Glob patterns** — `*`, `delete_*`, `*_execute` match tool names
- **Argument matching** — `args_match` / `args_not_match` inspect arguments (case-insensitive substring)
- **Shell safety** — `shell_safe` blocks metacharacters; `command_allowlist` restricts to known-good binaries
- **Path resolution** — `path_match` / `path_not_match` with symlink resolution, `~` and `$HOME` expansion
- **Content scanning** — `content_scan` detects secrets, PII, and prompt injection in arguments
- **Rate limiting** — sliding window (`10s`, `5m`, `1h`)
- **Approval gates** — `require_approval` pauses until a human grants or rejects
- **Enforcement levels** — `hard` (default), `soft`, or `advisory`
- **First-match-wins** — order matters, put specific rules before general ones

> Full reference: [`docs/policy-reference.md`](docs/policy-reference.md)

## CLI

### Setup & Policy

```bash
avakill setup                              # Interactive setup — detects agents, builds policy, installs hooks
avakill validate avakill.yaml              # Validate a policy file
avakill rules                              # Browse and toggle catalog rules
avakill rules list                         # Show all rules with sources
avakill rules create                       # Interactive custom rule creation
avakill reset                              # Factory-reset AvaKill
```

### Hooks & MCP

```bash
avakill hook install --agent all           # Install hooks for detected agents
avakill hook list                          # Show hook status
avakill mcp-wrap --agent all               # Wrap MCP servers with policy enforcement
avakill mcp-unwrap --agent all             # Restore original MCP configs
```

### Monitoring & Recovery

```bash
avakill fix                                # See why a call was blocked and how to fix it
avakill logs --denied-only --since 1h      # Query audit logs
avakill logs tail                          # Follow new events in real-time
avakill tracking on                        # Enable activity tracking
```

### Evaluate & Approve

```bash
echo '{"tool": "Bash", "args": {"command": "rm -rf /"}}' | avakill evaluate --policy avakill.yaml
avakill review avakill.proposed.yaml       # Review proposed policy changes
avakill approve avakill.proposed.yaml      # Activate proposed policy (human-only)
avakill approvals list                     # List pending approval requests
avakill approvals grant REQUEST_ID         # Approve a pending request
```

### Daemon

```bash
avakill daemon start --policy avakill.yaml # Start persistent daemon (optional)
avakill daemon status                      # Check daemon status
avakill daemon stop                        # Stop daemon
```

### Security & Compliance

```bash
avakill keygen                             # Generate Ed25519 keypair
avakill sign avakill.yaml                  # Sign policy
avakill verify avakill.yaml                # Verify signature
avakill harden avakill.yaml                # Set OS-level immutable flags
avakill compliance report --framework soc2 # Compliance assessment
avakill compliance gaps                    # Show compliance gaps
```

### Generate Policies with Any LLM

```bash
avakill schema --format=prompt             # Generate a prompt for any LLM
avakill schema --format=prompt --tools="execute_sql,shell_exec" --use-case="data pipeline"
avakill validate generated-policy.yaml     # Validate the LLM's output
```

## Why AvaKill?

|  | No Protection | Prompt Guardrails | **AvaKill** |
|---|:---:|:---:|:---:|
| Stops destructive tool calls | :x: | :x: | :white_check_mark: |
| Works across all major agents | — | Partial | :white_check_mark: |
| Three independent enforcement paths | — | :x: | :white_check_mark: |
| Deterministic (no LLM needed) | — | :x: | :white_check_mark: |
| <1ms overhead | — | :x: (LLM round-trip) | :white_check_mark: |
| YAML-based policies | — | :x: | :white_check_mark: |
| Full audit trail | :x: | :x: | :white_check_mark: |
| Human-in-the-loop approvals | :x: | :x: | :white_check_mark: |
| Self-protection (anti-tampering) | :x: | :x: | :white_check_mark: |
| Open source | — | Some | :white_check_mark: AGPL 3.0 |

## Roadmap

### Stable

- [x] Core policy engine with glob patterns, argument matching, rate limiting
- [x] Interactive setup wizard with 81-rule catalog (`avakill setup`)
- [x] Native agent hooks (Claude Code, Cursor, Windsurf, Gemini CLI, Codex)
- [x] MCP proxy with `avakill mcp-wrap` and `avakill-shim` (Go binary)
- [x] OS-level sandboxing — Landlock, sandbox-exec, Tetragon, AppContainer
- [x] Standalone hook mode (no daemon required)
- [x] Persistent daemon with Unix socket (<5ms evaluation)
- [x] Shell safety (`shell_safe` + `command_allowlist`)
- [x] Path resolution with symlink detection, `~` and `$HOME` expansion
- [x] Content scanning (secrets, PII, prompt injection)
- [x] SQLite audit logging with async batched writes
- [x] Tool name normalization across agents
- [x] Multi-level policy cascade (system/global/project/local)
- [x] Human-in-the-loop approval workflows
- [x] Policy propose / review / approve workflow
- [x] Recovery UX (`avakill fix`)
- [x] Self-protection (hardcoded anti-tampering rules)
- [x] Policy signing (HMAC-SHA256 + Ed25519)
- [x] Compliance reports (SOC 2, NIST AI RMF, EU AI Act, ISO 42001)
- [x] `@protect` decorator for any Python function
- [x] Framework wrappers (OpenAI, Anthropic, LangChain/LangGraph)
- [x] `avakill rules` for post-setup rule management

### Planned

- [ ] Real-time monitoring dashboard
- [ ] MCP HTTP transport proxy (Streamable HTTP)
- [ ] Slack / webhook / PagerDuty notifications
- [ ] CrewAI / AutoGen / custom framework interceptors

## Contributing

We welcome contributions! AvaKill is early-stage and there's a lot to build.

```bash
git clone https://github.com/log-bell/avakill.git
cd avakill
make dev    # Install in dev mode with all dependencies
make test   # Run the test suite
```

See [**CONTRIBUTING.md**](CONTRIBUTING.md) for the full guide — architecture overview, code style, and PR process.

## License

[AGPL-3.0](LICENSE) — free to use, modify, and distribute. If you offer AvaKill as a network service, you must release your source code under the same license. See [LICENSE](LICENSE) for details.

---

<div align="center">

*She doesn't guard. She kills.*

**If AvaKill would have saved you from an AI agent disaster, [give it a star](https://github.com/log-bell/avakill).**

Built because an AI agent tried to `DROP TABLE users` on a Friday afternoon.

</div>
