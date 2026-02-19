<div align="center">

# :shield: AvaKill

### She doesn't guard. She kills.

*Open-source safety firewall for AI agents*

[![PyPI version](https://img.shields.io/pypi/v/avakill?color=blue)](https://pypi.org/project/avakill/)
[![Python](https://img.shields.io/pypi/pyversions/avakill)](https://pypi.org/project/avakill/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/log-bell/avakill/ci.yml?branch=main&label=tests)](https://github.com/log-bell/avakill/actions)
[![GitHub stars](https://img.shields.io/github/stars/log-bell/avakill?style=social)](https://github.com/log-bell/avakill)

**Stop your AI agents from deleting your database, wiping your files, or going rogue.**

[Quickstart](#quickstart) · [Tutorial](docs/tutorial-you-couldve-invented-avakill.md) · [Integrations](#framework-integrations) · [Policy Reference](#policy-configuration) · [Security](docs/security-hardening.md) · [Deployment](docs/deployment.md) · [CLI](docs/cli-reference.md) · [Cookbook](docs/cookbook.md) · [API](docs/api-reference.md) · [Contributing](CONTRIBUTING.md)

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
pip install avakill
avakill init
```

> **Tip:** On macOS, use `pipx install avakill` or create a virtualenv first (`python3 -m venv .venv && source .venv/bin/activate`). System Python on macOS 14+ blocks global pip installs.

```python
from avakill import Guard, protect

guard = Guard()  # Loads avakill.yaml from current directory

@protect(guard=guard)
def search_users(query: str) -> str:
    return db.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{query}%",))

@protect(guard=guard)
def delete_user(user_id: str):
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))

search_users(query="active")   # ✅ Allowed — read operations pass through
delete_user(user_id="123")     # ❌ Blocked — PolicyViolation raised
```

Two commands, four lines of code. Safe calls pass through, destructive calls are killed before they execute.

## Features

<table>
<tr>
<td width="50%">

:lock: **Tool-Call Interception**<br>
Block destructive operations before they execute. Works at the function level — no prompt engineering required.

</td>
<td width="50%">

:clipboard: **YAML Policies**<br>
Simple, readable safety rules anyone can write. Glob patterns, argument matching, rate limiting — all in a single file.

</td>
</tr>
<tr>
<td>

:electric_plug: **Framework Agnostic**<br>
Drop-in support for OpenAI, Anthropic, LangChain, LangGraph, MCP, and any Python function via decorator.

</td>
<td>

:bar_chart: **Audit Trail**<br>
Complete SQLite log of every tool call and decision. Query with the CLI, export as JSON, or connect to your observability stack.

</td>
</tr>
<tr>
<td>

:zap: **Zero Overhead**<br>
<1ms per evaluation. No ML models, no external API calls. Pure in-process policy checks with thread-safe rate limiting.

</td>
<td>

:desktop_computer: **Live Dashboard**<br>
Real-time Rich terminal UI. Watch tool calls flow through, see what's blocked, track denial rates — all from your terminal.

</td>
</tr>
<tr>
<td>

:link: **MCP Proxy**<br>
Drop-in transparent proxy for any MCP server. One config change in Claude Desktop and every tool call is protected.

</td>
<td>

:arrows_counterclockwise: **Hot Reload**<br>
Update policies without restarting your agents. Call `guard.reload_policy()` or let the CLI handle it.

</td>
</tr>
<tr>
<td>

:satellite: **Native Agent Hooks**<br>
Drop-in hooks for Claude Code, Gemini CLI, Cursor, and Windsurf. One command to install — no code changes to your agent.

</td>
<td>

:gear: **Persistent Daemon**<br>
Unix socket server with <5ms evaluation. Start once, protect every agent on your machine. SIGHUP to reload policies.

</td>
</tr>
<tr>
<td>

:shield: **OS-Level Enforcement**<br>
Landlock (Linux), sandbox-exec (macOS), and Tetragon (Kubernetes). Kernel-level restrictions that even root can't bypass.

</td>
<td>

:scroll: **Compliance Reporting**<br>
Automated assessments for SOC 2, NIST AI RMF, EU AI Act, and ISO 42001. Generate reports in table, JSON, or Markdown format.

</td>
</tr>
</table>

## Why AvaKill?

|  | No Protection | Prompt Guardrails | **AvaKill** |
|---|:---:|:---:|:---:|
| Stops destructive tool calls | :x: | :x: | :white_check_mark: |
| Works across all frameworks | — | Partial | :white_check_mark: |
| Deterministic (no LLM needed) | — | :x: | :white_check_mark: |
| YAML-based policies | — | :x: | :white_check_mark: |
| Full audit trail | :x: | :x: | :white_check_mark: |
| MCP server support | — | :x: | :white_check_mark: |
| <1ms overhead | — | :x: (LLM round-trip) | :white_check_mark: |
| Native agent hooks (no code changes) | — | :x: | :white_check_mark: |
| OS-level kernel enforcement | — | :x: | :white_check_mark: |
| Open source | — | Some | :white_check_mark: AGPL 3.0 |

## Framework Integrations

### Native Agent Hooks

Protect AI coding agents with zero code changes — just install the hook:

```bash
avakill daemon start --policy avakill.yaml
avakill hook install --agent claude-code  # or gemini-cli, cursor, windsurf, all
avakill hook list
```

AvaKill intercepts every tool call at the agent level. Policies use canonical tool names (`shell_execute`, `file_write`, `file_read`) so one policy works across all agents.

> See [`docs/framework-integrations.md`](docs/framework-integrations.md#native-agent-hooks) for per-agent details and the full tool normalization table.

### OpenAI

```python
from openai import OpenAI
from avakill.interceptors.openai_wrapper import GuardedOpenAIClient

client = GuardedOpenAIClient(OpenAI(), policy="avakill.yaml")
response = client.chat.completions.create(model="gpt-4o", tools=[...], messages=[...])
# Denied tool_calls are automatically removed from the response
# All decisions available at: response.avakill_decisions
```

### Anthropic

```python
from anthropic import Anthropic
from avakill.interceptors.anthropic_wrapper import GuardedAnthropicClient

client = GuardedAnthropicClient(Anthropic(), policy="avakill.yaml")
response = client.messages.create(model="claude-sonnet-4-5-20250514", tools=[...], messages=[...])
# Denied tool_use blocks are removed from response.content
```

### LangChain / LangGraph

```python
from avakill.interceptors.langchain_handler import AvaKillCallbackHandler

handler = AvaKillCallbackHandler(policy="avakill.yaml")
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
# Raises PolicyViolation before the tool executes
```

### MCP Proxy (Claude Desktop, Cursor, etc.)

One config change — no code modifications to the MCP server:

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "database": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "avakill.yaml"
      ]
    }
  }
}
```

### Decorator (any Python function)

```python
from avakill import Guard, protect

guard = Guard(policy="avakill.yaml")

@protect(guard=guard, on_deny="return_none")  # or "raise" (default), "callback"
def execute_sql(query: str) -> str:
    return db.execute(query)
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

> See [`docs/llm-policy-prompt.md`](docs/llm-policy-prompt.md) for a paste-ready prompt.

## CLI

```bash
# Initialize a new policy file (auto-detects your framework)
avakill init

# Validate your policy file
avakill validate avakill.yaml

# Launch the real-time terminal dashboard
avakill dashboard

# Query audit logs
avakill logs --denied-only --since 1h
avakill logs --tool "execute_sql" --json
avakill logs tail  # Follow in real-time

# Start the MCP proxy
avakill mcp-proxy --upstream-cmd python --upstream-args server.py --policy avakill.yaml

# Export JSON Schema for the policy format
avakill schema

# Generate an LLM prompt for policy creation
avakill schema --format=prompt
avakill schema --format=prompt --tools="file_read,shell_exec" --use-case="code assistant"

# Start the persistent daemon
avakill daemon start --policy avakill.yaml

# Evaluate a tool call via the daemon
echo '{"tool": "shell_execute", "args": {"command": "rm -rf /"}}' | avakill evaluate --agent cli

# Install hooks for all detected agents
avakill hook install --agent all
avakill hook list

# Generate OS-level enforcement
avakill enforce landlock --policy avakill.yaml --dry-run
avakill enforce sandbox --policy avakill.yaml --output avakill.sb

# Run compliance assessment
avakill compliance report --framework soc2 --policy avakill.yaml
avakill compliance gaps --policy avakill.yaml

# Manage approval workflows
avakill approvals list
avakill approvals grant REQUEST_ID
```

## Dashboard

The dashboard shows:
- **Safety overview** — total, allowed, denied, and pending counts with percentages
- **Live tool calls** — real-time stream with tool name, action, policy, and argument previews
- **Top denied tools** — bar chart of the most frequently blocked tools
- **Keyboard shortcuts** — `q` quit, `r` reload policy, `c` clear

## Architecture

```
┌─────────────────┐     ┌─────────────────────────────────────────────────┐     ┌──────────┐
│                  │     │              AvaKill                            │     │          │
│  AI Agent        │     │                                                 │     │   Tool   │
│  (Claude Code,   │────>│  Native Hook ──> Daemon ──> Policy ──> Log     │────>│          │
│   Gemini CLI,    │     │       │              │           │               │     │          │
│   Cursor, etc.)  │     │       │         ┌────┴────┐     │               │     └──────────┘
│                  │     │       │      Allow      Deny    │               │
└─────────────────┘     │       │         │         │ ──> Audit Log       │
                        │       │         v         v      │               │
                        │       │   Forward to    Block &  │               │
                        │       │     Tool       Return    │               │
                        │       │                Error     │               │
                        │       v                          v               │
                        │  ┌─ OS Enforcement ──────────────────────────┐   │
                        │  │ Landlock · sandbox-exec · Tetragon        │   │
                        │  └───────────────────────────────────────────┘   │
                        └─────────────────────────────────────────────────┘
```

AvaKill protects your agents at multiple levels: **native hooks** intercept tool calls at the agent level, a **persistent daemon** provides sub-5ms evaluation over a Unix socket, **policy rules** enforce first-match-wins logic with glob patterns and rate limiting, and **OS-level enforcement** (Landlock, sandbox-exec, Tetragon) provides kernel-level restrictions.

**Core components:**
- **`Guard`** — the main entry point. Wraps a `PolicyEngine`, records audit events.
- **`PolicyEngine`** — parses YAML, evaluates tool calls against rules with first-match-wins logic.
- **Interceptors** — framework-specific wrappers (OpenAI, Anthropic, LangChain, decorator).
- **MCP Proxy** — transparent stdio proxy that sits in front of any MCP server.
- **Audit Logger** — async SQLite logger with batched writes and WAL mode.
- **Event Bus** — in-process pub/sub for real-time dashboard and monitoring.
- **`DaemonServer`** — persistent Unix socket server for <5ms evaluation without in-process integration.
- **`Hook Adapters`** — native integrations for Claude Code, Gemini CLI, Cursor, and Windsurf.
- **`ToolNormalizer`** — translates agent-specific tool names to canonical names for universal policies.
- **`PolicyCascade`** — discovers and merges policies from system, global, project, and local levels.
- **`Enforcement Backends`** — Landlock (Linux), sandbox-exec (macOS), and Tetragon (Kubernetes) for OS-level restrictions.
- **`ComplianceAssessor`** — automated compliance checks for SOC 2, NIST AI RMF, EU AI Act, and ISO 42001.

## Roadmap

### Stable

Core features with extensive test coverage, ready for production use.

- [x] Core policy engine with glob patterns, argument matching, rate limiting
- [x] OpenAI, Anthropic, LangChain/LangGraph interceptors
- [x] `@protect` decorator for any Python function
- [x] MCP transparent proxy (stdio transport)
- [x] SQLite audit logging with async batched writes
- [x] Rich terminal dashboard with live event stream
- [x] CLI: `init`, `validate`, `logs`, `dashboard`, `mcp-proxy`, `schema`
- [x] Hot-reload with file watcher
- [x] Persistent daemon with Unix socket (<5ms evaluation)
- [x] Agent hook adapters (Claude Code, Gemini CLI, Cursor, Windsurf)
- [x] Tool name normalization across agents
- [x] Multi-level policy cascade (system/global/project/local)

### Shipped (beta)

Implemented and tested. Maturing toward stable in upcoming releases.

- [x] Policy signing (HMAC-SHA256 + Ed25519)
- [x] Self-protection (hardcoded anti-tampering rules)
- [x] OS-level hardening (chattr/schg, SELinux, AppArmor, seccomp)
- [x] C-level audit hooks (optional hardened extension)
- [x] OpenTelemetry + Prometheus observability
- [x] Enforcement levels (hard/soft/advisory)
- [x] OS-level enforcement (Landlock, macOS sandbox-exec, Tetragon)
- [x] Compliance reports (SOC 2, NIST AI RMF, EU AI Act, ISO 42001)
- [x] Human-in-the-loop approval workflows
- [x] Audit analytics engine

### Planned

- [ ] Web dashboard (Next.js)
- [ ] Slack / webhook / PagerDuty notifications
- [ ] MCP HTTP transport proxy (Streamable HTTP)
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

**If AvaKill would have saved you from an AI agent disaster, [give it a star](https://github.com/log-bell/avakill).**

Built because an AI agent tried to `DROP TABLE users` on a Friday afternoon.

</div>
