<div align="center">

# :shield: AvaKill

### Open-source safety firewall for AI coding agents

[![PyPI version](https://img.shields.io/pypi/v/avakill?color=blue)](https://pypi.org/project/avakill/)
[![Python](https://img.shields.io/pypi/pyversions/avakill)](https://pypi.org/project/avakill/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/log-bell/avakill/ci.yml?branch=main&label=tests)](https://github.com/log-bell/avakill/actions)
![Tests](https://img.shields.io/badge/tests-1%2C183%20passing-brightgreen)
![Red Team](https://img.shields.io/badge/red%20team-30%2F30%20blocked-red)
[![GitHub stars](https://img.shields.io/github/stars/log-bell/avakill?style=social)](https://github.com/log-bell/avakill)

**Stop your AI agents from deleting your database, wiping your files, or going rogue.**

<!-- TODO: Add terminal GIF here showing attack interception -->
> :tv: **[Watch the demo →](#demo)** See AvaKill block a live red team attack in real-time.

```bash
pipx install avakill    # Recommended
# or: pip install avakill
```

[Quickstart](#quickstart) · [How It Works](#architecture) · [Integrations](#integrations) · [Policy Reference](#policy-configuration) · [CLI](#cli) · [Contributing](CONTRIBUTING.md)

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
avakill guide          # Interactive setup — detects agents, generates policy, installs hooks
```

> **Tip:** On macOS, use `pipx install avakill` (recommended). System Python on macOS 14+ blocks global pip installs.

That's it — two commands, zero code changes. AvaKill detects your AI agents, generates a safety policy, and installs hooks. Now when an agent tries something dangerous:

```bash
echo '{"tool": "Bash", "args": {"command": "rm -rf /"}}' | avakill evaluate --policy avakill.yaml
# deny: Matched rule 'block-dangerous-shells'
```

Safe calls pass through. Destructive calls are killed before they execute.

## Features

<table>
<tr>
<td width="50%">

:lock: **Tool-Call Interception**<br>
Block destructive operations before they execute. Works at the agent hook level — no prompt engineering required.

</td>
<td width="50%">

:clipboard: **YAML Policies**<br>
Simple, readable safety rules anyone can write. Glob patterns, argument matching, rate limiting — all in a single file.

</td>
</tr>
<tr>
<td>

:satellite: **Native Agent Hooks**<br>
Drop-in hooks for Claude Code, Gemini CLI, Windsurf, and OpenAI Codex. One policy protects every agent.

</td>
<td>

:bar_chart: **Audit Trail**<br>
Complete SQLite log of every tool call and decision. Query with the CLI, export as JSON, live tail in real-time.

</td>
</tr>
<tr>
<td>

:zap: **Zero Overhead**<br>
<1ms per evaluation. No ML models, no external API calls. Pure in-process policy checks with thread-safe rate limiting.

</td>
<td>

:wrench: **Recovery UX**<br>
`avakill fix` shows why a call was blocked and exactly how to unblock it — recovery hints, YAML snippets, and actionable steps.

</td>
</tr>
<tr>
<td>

:raised_hand: **Human-in-the-Loop Approvals**<br>
`require_approval` policy action pauses execution until a human grants or rejects. Full approval workflow via CLI.

</td>
<td>

:arrows_counterclockwise: **Hot Reload**<br>
Update policies without restarting your agents. The daemon reloads on SIGHUP, or use `avakill dashboard` to reload live.

</td>
</tr>
<tr>
<td>

:shield: **Self-Protection**<br>
Built-in anti-tampering rules prevent agents from disabling their own guardrails — hardcoded, not configurable.

</td>
<td>

:gear: **Persistent Daemon**<br>
Unix socket server with <5ms evaluation. Start once, protect every agent on your machine.

</td>
</tr>
<tr>
<td>

:key: **Policy Integrity**<br>
Sign policies with HMAC-SHA256 or Ed25519. Verify signatures before enforcement. Detect tampering.

</td>
<td>

:page_facing_up: **Propose / Review / Approve**<br>
Safe policy change workflow — propose changes, review diffs, approve with backup and optional auto-signing.

</td>
</tr>
</table>

## Why AvaKill?

|  | No Protection | Prompt Guardrails | **AvaKill** |
|---|:---:|:---:|:---:|
| Stops destructive tool calls | :x: | :x: | :white_check_mark: |
| Works across all major agents | — | Partial | :white_check_mark: |
| Deterministic (no LLM needed) | — | :x: | :white_check_mark: |
| YAML-based policies | — | :x: | :white_check_mark: |
| Full audit trail | :x: | :x: | :white_check_mark: |
| Human-in-the-loop approvals | :x: | :x: | :white_check_mark: |
| <1ms overhead | — | :x: (LLM round-trip) | :white_check_mark: |
| Native agent hooks (no code changes) | — | :x: | :white_check_mark: |
| Open source | — | Some | :white_check_mark: AGPL 3.0 |

## Integrations

### Native Agent Hooks

Protect AI coding agents with zero code changes — just install the hook:

```bash
# Install hooks for your agents (works standalone — no daemon required)
avakill hook install --agent claude-code  # or gemini-cli, windsurf, openai-codex, all
avakill hook list

# Optional: start the daemon for sub-5ms shared evaluation
avakill daemon start --policy avakill.yaml
```

Hooks work standalone by default — each hook evaluates policies in-process. The daemon is optional and provides shared state (rate limits, audit) across agents.

AvaKill intercepts every tool call at the agent level. Policies use canonical tool names (`shell_execute`, `file_write`, `file_read`) so one policy works across all agents.

**Supported agents:**

| Agent | Hook Status |
|---|---|
| Claude Code | Battle-tested |
| Gemini CLI | Supported |
| Windsurf | Supported |
| OpenAI Codex | Supported (pending upstream hook API) |

> **Other agents:** Cursor, Cline, and Continue are available via MCP wrapping or the Python SDK.

### Python SDK

For programmatic integration, AvaKill's `Guard` is also available as a Python API:

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
from avakill.interceptors.openai_wrapper import GuardedOpenAIClient
client = GuardedOpenAIClient(OpenAI(), policy="avakill.yaml")

# Anthropic
from avakill.interceptors.anthropic_wrapper import GuardedAnthropicClient
client = GuardedAnthropicClient(Anthropic(), policy="avakill.yaml")

# LangChain / LangGraph
from avakill.interceptors.langchain_handler import AvaKillCallbackHandler
handler = AvaKillCallbackHandler(policy="avakill.yaml")
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
```

> See [`examples/`](examples/) for complete runnable demos of every integration.

## Policy Configuration

Policies are YAML files. Rules are evaluated top-to-bottom — first match wins.

```yaml
version: "1.0"
default_action: deny  # Block everything not explicitly allowed

policies:
  # Allow read operations
  - name: "allow-reads"
    tools: ["search_*", "*_query", "*_get", "*_list"]
    action: allow

  # Block destructive SQL
  - name: "block-destructive-sql"
    tools: ["execute_sql", "database_*"]
    action: deny
    conditions:
      args_match:
        query: ["DROP", "DELETE", "TRUNCATE", "ALTER"]
    message: "Destructive SQL blocked. Use a manual migration."

  # Allow safe SQL (SELECT, INSERT, UPDATE)
  - name: "allow-safe-sql"
    tools: ["execute_sql", "database_*"]
    action: allow

  # Block dangerous shell commands
  - name: "block-dangerous-shells"
    tools: ["shell_execute", "run_command"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777", "> /dev/"]
    message: "Dangerous shell command blocked."

  # Allow safe shell commands
  - name: "allow-safe-shells"
    tools: ["shell_execute", "run_command"]
    action: allow

  # Require human approval for file writes
  - name: "approve-writes"
    tools: ["file_write"]
    action: require_approval
    message: "File writes require human approval."

  # Rate limit API calls
  - name: "rate-limit-search"
    tools: ["web_search"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "60s"

  # Block all destructive operations by pattern
  - name: "block-destructive"
    tools: ["delete_*", "remove_*", "destroy_*", "drop_*"]
    action: deny
    message: "Destructive operations require manual execution."
```

**Policy features:**
- **Glob patterns** — `*`, `delete_*`, `*_execute` match tool names
- **Argument matching** — `args_match` / `args_not_match` inspect arguments (case-insensitive substring)
- **Rate limiting** — sliding window (`10s`, `5m`, `1h`)
- **Approval gates** — `require_approval` pauses until a human grants or rejects
- **Environment variables** — `${VAR_NAME}` substitution in YAML
- **First-match-wins** — order matters, put specific rules before general ones

> Full reference: [`docs/policy-reference.md`](docs/policy-reference.md)

## Generate Policies with Any LLM

Don't want to write YAML by hand? Use any LLM to generate policies for you:

```bash
# Generate a prompt, paste it into ChatGPT/Claude/Gemini, describe your agent
avakill schema --format=prompt

# Include your actual tool names for a tailored prompt
avakill schema --format=prompt --tools="execute_sql,shell_exec,file_write" --use-case="data pipeline"

# Validate the LLM's output
avakill validate generated-policy.yaml
```

Or use the JSON Schema directly with structured output APIs:

```python
from avakill import get_json_schema, generate_prompt

schema = get_json_schema()          # For structured output / validation
prompt = generate_prompt()           # Self-contained LLM prompt
```

## CLI

### Core Commands

```bash
# Interactive setup — detects agents, generates policy, installs hooks
avakill guide

# Validate your policy file
avakill validate avakill.yaml

# Evaluate a tool call against policy
echo '{"tool": "Bash", "args": {"command": "rm -rf /"}}' | avakill evaluate --policy avakill.yaml

# See why a call was blocked and how to fix it
avakill fix --db avakill_audit.db

# Install hooks for all detected agents
avakill hook install --agent all
avakill hook list

# Query audit logs
avakill logs --db avakill_audit.db --denied-only --since 1h
avakill logs --db avakill_audit.db --tool Bash --json
avakill logs --db avakill_audit.db tail  # Live tail

# Review and approve policy changes
avakill review avakill.proposed.yaml
avakill approve avakill.proposed.yaml

# Start the persistent daemon
avakill daemon start --policy avakill.yaml --log-db avakill_audit.db
avakill daemon status
avakill daemon stop

# Manage human-in-the-loop approvals
avakill approvals list
avakill approvals grant REQUEST_ID
avakill approvals reject REQUEST_ID
```

### Advanced Commands

```bash
# Policy signing (HMAC-SHA256 or Ed25519)
avakill keygen                           # Generate Ed25519 keypair
avakill sign avakill.yaml                # Sign policy
avakill verify avakill.yaml              # Verify signature

# OS-level file protection
avakill harden avakill.yaml              # Set immutable flags (requires sudo)
avakill check-hardening avakill.yaml     # Report hardening status

# Export JSON Schema / LLM prompt
avakill schema
avakill schema --format=prompt --tools="Bash,Write" --use-case="code assistant"

# Agent containment profiles
avakill profile list
avakill profile show openclaw

# Real-time terminal dashboard
avakill dashboard --db avakill_audit.db --policy avakill.yaml --watch
```

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────────────────────┐     ┌──────────┐
│                  │     │              AvaKill                         │     │          │
│  AI Agent        │     │                                              │     │   Tool   │
│  (Claude Code,   │────>│  Hook ──> Daemon ──> Guard ──> Policy ──> Log│────>│          │
│   Gemini CLI,    │     │                        │           │         │     │          │
│   Windsurf, etc.) │     │                   ┌────┴────┐      │         │     └──────────┘
│                  │     │                Allow    Deny/     │         │
└─────────────────┘     │                  │     Approve     │         │
                        │                  v       │         │         │
                        │            Forward to   Block &   Audit     │
                        │              Tool      Return     Log      │
                        │                        Error               │
                        └──────────────────────────────────────────────┘
```

AvaKill protects your agents at multiple levels: **native hooks** intercept tool calls at the agent level, a **persistent daemon** provides sub-5ms evaluation over a Unix socket, and **policy rules** enforce first-match-wins logic with glob patterns, rate limiting, and human-in-the-loop approval gates.

**Core components:**
- **`Guard`** — the main entry point. Wraps a `PolicyEngine`, records audit events. Also available as a Python API via `Guard.evaluate(tool, args)`.
- **`PolicyEngine`** — parses YAML, evaluates tool calls against rules with first-match-wins logic.
- **`Audit Logger`** — async SQLite logger with batched writes and WAL mode.
- **`Event Bus`** — in-process pub/sub for real-time dashboard and monitoring.
- **`DaemonServer`** — persistent Unix socket server for <5ms evaluation without in-process integration.
- **`Hook Adapters`** — native integrations for Claude Code, Gemini CLI, Windsurf, and OpenAI Codex.
- **`ToolNormalizer`** — translates agent-specific tool names to canonical names for universal policies.
- **`PolicyCascade`** — discovers and merges policies from system, global, project, and local levels.
- **`ApprovalStore`** — SQLite-backed human-in-the-loop approval workflow.
- **`PolicyIntegrity`** — HMAC-SHA256 + Ed25519 policy signing and verification.

## Roadmap

### Stable

Core features, battle-tested and ready for production use.

- [x] Core policy engine with glob patterns, argument matching, rate limiting
- [x] Interactive setup wizard (`avakill guide`)
- [x] Native agent hooks (Claude Code, Gemini CLI, Windsurf, OpenAI Codex)
- [x] Fail-closed mode (`AVAKILL_FAIL_CLOSED=1`)
- [x] Standalone hook mode (no daemon required)
- [x] Persistent daemon with Unix socket (<5ms evaluation)
- [x] SQLite audit logging with async batched writes
- [x] Tool name normalization across agents
- [x] Multi-level policy cascade (system/global/project/local)
- [x] Human-in-the-loop approval workflows
- [x] Policy propose / review / approve workflow
- [x] Recovery UX (`avakill fix`)
- [x] Self-protection (hardcoded anti-tampering rules)

### Advanced

Shipped and tested. Available for security-conscious and enterprise users.

- [x] Policy signing (HMAC-SHA256 + Ed25519)
- [x] OS-level file hardening (chattr/schg immutable flags)
- [x] Agent containment profiles
- [x] JSON Schema export + LLM prompt generation
- [x] Rich terminal dashboard with live event stream
- [x] `@protect` decorator for any Python function
- [x] Framework wrappers (OpenAI, Anthropic, LangChain/LangGraph)

### Shipped (untested)

Code complete with unit tests, but not yet validated on real infrastructure.

- [x] Cursor hooks (code-complete, not battle-tested)
- [x] OS-level enforcement — Landlock (Linux), sandbox-exec (macOS), Tetragon (Kubernetes), Windows AppContainer
- [x] MCP transparent proxy (stdio transport)
- [x] Compliance reports (SOC 2, NIST AI RMF, EU AI Act, ISO 42001)
- [x] OpenTelemetry + Prometheus observability

### Planned

- [ ] MCP HTTP transport proxy (Streamable HTTP)
- [ ] Web dashboard (Next.js)
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
